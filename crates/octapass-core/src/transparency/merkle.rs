//! The RFC 9162 Merkle tree (section 2.1): hashes, audit paths, consistency proofs, and the
//! frontier a monitor keeps so it can rebuild the root from new leaves alone.

use core::ops::Range;

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub fn leaf_hash(leaf: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([0x00])
        .chain_update(leaf)
        .finalize()
        .into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([0x01])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The hash of an empty tree: SHA-256 of nothing.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// A perfect subtree: `2^level` leaves, the `index`th of that size from the left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId {
    pub level: u32,
    pub index: u64,
}

/// The largest power of two below `n` (`n` ≥ 2): where the tree splits.
fn split(n: u64) -> u64 {
    1 << (63 - (n - 1).leading_zeros())
}

fn path(leaf: u64, range: Range<u64>, out: &mut Vec<Range<u64>>) {
    let size = range.end - range.start;
    if size <= 1 {
        return;
    }
    let middle = range.start + split(size);
    if leaf < middle {
        path(leaf, range.start..middle, out);
        out.push(middle..range.end);
    } else {
        path(leaf, middle..range.end, out);
        out.push(range.start..middle);
    }
}

/// The subtrees of the audit path for `leaf` in a tree of `size` leaves, in proof order.
pub fn inclusion_ranges(leaf: u64, size: u64) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    path(leaf, 0..size, &mut out);
    out
}

fn subproof(old_end: u64, range: Range<u64>, whole: bool, out: &mut Vec<Range<u64>>) {
    if old_end == range.end {
        if !whole {
            out.push(range);
        }
        return;
    }
    let middle = range.start + split(range.end - range.start);
    if old_end <= middle {
        subproof(old_end, range.start..middle, whole, out);
        out.push(middle..range.end);
    } else {
        subproof(old_end, middle..range.end, false, out);
        out.push(range.start..middle);
    }
}

/// The subtrees of the consistency proof from `old_size` to `new_size`, in proof order.
pub fn consistency_ranges(old_size: u64, new_size: u64) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    if old_size != 0 && old_size < new_size {
        subproof(old_size, 0..new_size, true, &mut out);
    }
    out
}

/// The perfect subtrees that make up `range`, largest first. Their hashes, folded with
/// [`fold_nodes`], give the range's tree hash.
pub fn range_nodes(range: Range<u64>) -> Vec<NodeId> {
    let mut nodes = Vec::new();
    let mut start = range.start;
    while start < range.end {
        let remaining = range.end - start;
        let aligned = if start == 0 {
            u32::MAX
        } else {
            start.trailing_zeros()
        };
        let level = aligned.min(63 - remaining.leading_zeros());
        nodes.push(NodeId {
            level,
            index: start >> level,
        });
        start += 1 << level;
    }
    nodes
}

/// The tree hash of a range from its perfect subtrees, as [`range_nodes`] lists them.
pub fn fold_nodes(nodes: &[Hash]) -> Option<Hash> {
    let (last, rest) = nodes.split_last()?;
    Some(
        rest.iter()
            .rev()
            .fold(*last, |right, left| node_hash(left, &right)),
    )
}

/// The perfect subtrees completed by appending leaf `index`, lowest first, as
/// `(node, left sibling)`. Each node's hash is `node_hash(left sibling, the node below)`.
pub fn completed_parents(index: u64) -> Vec<(NodeId, NodeId)> {
    let mut parents = Vec::new();
    let mut at = index;
    let mut level = 0;
    while at & 1 == 1 {
        parents.push((
            NodeId {
                level: level + 1,
                index: at >> 1,
            },
            NodeId {
                level,
                index: at - 1,
            },
        ));
        at >>= 1;
        level += 1;
    }
    parents
}

/// RFC 9162 section 2.1.3.2.
pub fn verify_inclusion(leaf: u64, size: u64, hash: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if leaf >= size {
        return false;
    }
    let (mut node, mut last) = (leaf, size - 1);
    let mut acc = *hash;
    for sibling in proof {
        if last == 0 {
            return false;
        }
        if node & 1 == 1 || node == last {
            acc = node_hash(sibling, &acc);
            while node & 1 == 0 && node != 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            acc = node_hash(&acc, sibling);
        }
        node >>= 1;
        last >>= 1;
    }
    last == 0 && acc == *root
}

/// RFC 9162 section 2.1.4.2.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    let mut hashes = proof.iter();
    let first = if old_size.is_power_of_two() {
        old_root
    } else {
        match hashes.next() {
            Some(hash) => hash,
            None => return false,
        }
    };
    let (mut node, mut last) = (old_size - 1, new_size - 1);
    while node & 1 == 1 {
        node >>= 1;
        last >>= 1;
    }
    let (mut old_acc, mut new_acc) = (*first, *first);
    for sibling in hashes {
        if last == 0 {
            return false;
        }
        if node & 1 == 1 || node == last {
            old_acc = node_hash(sibling, &old_acc);
            new_acc = node_hash(sibling, &new_acc);
            while node & 1 == 0 && node != 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            new_acc = node_hash(&new_acc, sibling);
        }
        node >>= 1;
        last >>= 1;
    }
    last == 0 && old_acc == *old_root && new_acc == *new_root
}

/// The perfect subtrees covering the first `size` leaves, largest first: all a monitor needs to
/// keep to go on appending leaves and computing the root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frontier {
    size: u64,
    nodes: Vec<Hash>,
}

impl Frontier {
    /// `None` when `nodes` can't be the frontier of a tree of that size.
    pub fn from_nodes(size: u64, nodes: Vec<Hash>) -> Option<Self> {
        (nodes.len() == size.count_ones() as usize).then_some(Self { size, nodes })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn nodes(&self) -> &[Hash] {
        &self.nodes
    }

    pub fn push(&mut self, hash: Hash) {
        let mut hash = hash;
        let mut at = self.size;
        while at & 1 == 1 {
            let left = self.nodes.pop().expect("one node per set bit of the size");
            hash = node_hash(&left, &hash);
            at >>= 1;
        }
        self.nodes.push(hash);
        self.size += 1;
    }

    pub fn root(&self) -> Hash {
        fold_nodes(&self.nodes).unwrap_or_else(empty_root)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn hex(text: &str) -> Hash {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// The eight-leaf tree from the Certificate Transparency reference tests, with the root of
    /// every prefix.
    const LEAVES: [&[u8]; 8] = [
        b"",
        b"\x00",
        b"\x10",
        b"\x20\x21",
        b"\x30\x31",
        b"\x40\x41\x42\x43",
        b"\x50\x51\x52\x53\x54\x55\x56\x57",
        b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
    ];
    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    /// A stored tree: every completed perfect subtree, as the server keeps them.
    struct Tree {
        size: u64,
        nodes: HashMap<(u32, u64), Hash>,
    }

    impl Tree {
        fn new(count: u64) -> Self {
            let mut tree = Self {
                size: 0,
                nodes: HashMap::new(),
            };
            for i in 0..count {
                tree.append(leaf_hash(&i.to_be_bytes()));
            }
            tree
        }

        fn append(&mut self, hash: Hash) {
            let index = self.size;
            self.nodes.insert((0, index), hash);
            let mut below = hash;
            for (node, left) in completed_parents(index) {
                below = node_hash(&self.nodes[&(left.level, left.index)], &below);
                self.nodes.insert((node.level, node.index), below);
            }
            self.size += 1;
        }

        fn hash(&self, range: Range<u64>) -> Hash {
            let hashes: Vec<Hash> = range_nodes(range)
                .iter()
                .map(|node| self.nodes[&(node.level, node.index)])
                .collect();
            fold_nodes(&hashes).unwrap()
        }

        fn proof(&self, ranges: Vec<Range<u64>>) -> Vec<Hash> {
            ranges.into_iter().map(|range| self.hash(range)).collect()
        }

        fn root(&self, size: u64) -> Hash {
            self.hash(0..size)
        }
    }

    #[test]
    fn matches_the_certificate_transparency_vectors() {
        assert_eq!(
            empty_root(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let mut frontier = Frontier::default();
        let mut tree = Tree::new(0);
        for (leaf, root) in LEAVES.iter().zip(ROOTS) {
            let hash = leaf_hash(leaf);
            frontier.push(hash);
            tree.append(hash);
            assert_eq!(frontier.root(), hex(root));
            assert_eq!(tree.root(tree.size), hex(root));
        }
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_of_every_size() {
        let tree = Tree::new(70);
        for size in 1..=70 {
            let root = tree.root(size);
            for leaf in 0..size {
                let hash = leaf_hash(&leaf.to_be_bytes());
                let proof = tree.proof(inclusion_ranges(leaf, size));
                assert!(verify_inclusion(leaf, size, &hash, &proof, &root));
                assert!(!verify_inclusion(leaf, size, &[9; 32], &proof, &root));
                assert!(!verify_inclusion(size, size, &hash, &proof, &root));
                if let Some((_, shorter)) = proof.split_last() {
                    assert!(!verify_inclusion(leaf, size, &hash, shorter, &root));
                }
                let mut longer = proof.clone();
                longer.push([0; 32]);
                assert!(!verify_inclusion(leaf, size, &hash, &longer, &root));
            }
        }
    }

    #[test]
    fn consistency_proofs_verify_for_every_pair_of_sizes() {
        let tree = Tree::new(70);
        for new_size in 1..=70 {
            let new_root = tree.root(new_size);
            for old_size in 1..=new_size {
                let old_root = tree.root(old_size);
                let proof = tree.proof(consistency_ranges(old_size, new_size));
                assert!(
                    verify_consistency(old_size, new_size, &old_root, &new_root, &proof),
                    "{old_size} to {new_size}"
                );
                if old_size < new_size {
                    assert!(!verify_consistency(
                        old_size, new_size, &[7; 32], &new_root, &proof
                    ));
                    assert!(!verify_consistency(
                        old_size, new_size, &old_root, &[7; 32], &proof
                    ));
                    assert!(!verify_consistency(
                        new_size, old_size, &new_root, &old_root, &proof
                    ));
                    for changed in 0..proof.len() {
                        let mut bad = proof.clone();
                        bad[changed][0] ^= 1;
                        assert!(!verify_consistency(
                            old_size, new_size, &old_root, &new_root, &bad
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn a_rewritten_history_has_no_consistency_proof() {
        let honest = Tree::new(16);
        let mut forked = Tree::new(9);
        for i in 0..7u64 {
            forked.append(leaf_hash(&(1_000 + i).to_be_bytes()));
        }
        // The forked tree shares its first nine leaves, so the head at 10 is where they part.
        let proof = forked.proof(consistency_ranges(10, 16));
        assert!(!verify_consistency(
            10,
            16,
            &honest.root(10),
            &forked.root(16),
            &proof
        ));
    }

    #[test]
    fn an_empty_old_tree_needs_no_proof() {
        let tree = Tree::new(5);
        assert!(verify_consistency(0, 5, &empty_root(), &tree.root(5), &[]));
        assert!(!verify_consistency(
            0,
            5,
            &empty_root(),
            &tree.root(5),
            &[[0; 32]]
        ));
    }

    #[test]
    fn frontiers_match_the_nodes_a_server_stores() {
        let tree = Tree::new(70);
        for size in 0..=70 {
            let nodes: Vec<Hash> = range_nodes(0..size)
                .iter()
                .map(|node| tree.nodes[&(node.level, node.index)])
                .collect();
            let mut frontier = Frontier::from_nodes(size, nodes).unwrap();
            assert_eq!(frontier.size(), size);
            if size > 0 {
                assert_eq!(frontier.root(), tree.root(size));
            }
            // A monitor can pick up from any position.
            for i in size..70 {
                frontier.push(leaf_hash(&i.to_be_bytes()));
            }
            assert_eq!(frontier.root(), tree.root(70));
        }
        assert_eq!(Frontier::from_nodes(3, vec![[0; 32]]), None);
    }

    #[test]
    fn a_left_out_leaf_changes_the_root() {
        let tree = Tree::new(9);
        let mut frontier = Frontier::default();
        for i in (0..9u64).filter(|i| *i != 4) {
            frontier.push(leaf_hash(&i.to_be_bytes()));
        }
        assert_ne!(frontier.root(), tree.root(9));
    }
}
