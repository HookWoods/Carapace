use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct IsolationForest {
    pub trees: Vec<IsolationTree>,
    pub sample_size: usize,
    pub n_trees: usize,
}

pub struct IsolationTree {
    pub root: Option<Box<TreeNode>>,
}

pub struct TreeNode {
    pub split_attr: usize,
    pub split_value: f64,
    pub left: Option<Box<TreeNode>>,
    pub right: Option<Box<TreeNode>>,
    pub height: u32,
}

pub struct MLModel {
    pub model: IsolationForest,
    pub threshold: f64,
    pub feature_importance: Vec<f64>,
}