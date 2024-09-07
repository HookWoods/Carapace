use ndarray::{Array1, Array2, ArrayView1};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::cmp::Ordering;

pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    sample_size: usize,
    n_trees: usize,
}

struct IsolationTree {
    root: Option<Box<TreeNode>>,
}

struct TreeNode {
    split_attr: usize,
    split_value: f64,
    left: Option<Box<TreeNode>>,
    right: Option<Box<TreeNode>>,
    height: u32,
}

impl IsolationForest {
    pub fn new(n_trees: usize, sample_size: usize) -> Self {
        IsolationForest {
            trees: vec![],
            sample_size,
            n_trees,
        }
    }

    pub fn fit(&mut self, data: &Array2<f64>) {
        let mut rng = ChaCha8Rng::from_entropy();
        for _ in 0..self.n_trees {
            let sample = self.sample_data(data, &mut rng);
            let tree = IsolationTree::build(sample, 0, &mut rng);
            self.trees.push(tree);
        }
    }

    pub fn predict(&self, instance: &Array1<f64>) -> f64 {
        let avg_path_length: f64 = self.trees.iter()
            .map(|tree| tree.path_length(&instance.view()) as f64)
            .sum::<f64>() / self.n_trees as f64;

        let n = self.sample_size as f64;
        let c = 2.0 * (n - 1.0).ln() + 0.5772156649; // Euler's constant
        let score = 2.0_f64.powf(-avg_path_length / c);
        score
    }

    fn sample_data(&self, data: &Array2<f64>, rng: &mut ChaCha8Rng) -> Array2<f64> {
        let n_samples = data.nrows().min(self.sample_size);
        let indices: Vec<usize> = (0..data.nrows()).collect();
        let sampled_indices: Vec<usize> = indices.choose_multiple(rng, n_samples).cloned().collect();
        data.select(ndarray::Axis(0), &sampled_indices)
    }

    fn compute_feature_importance(&self, data: &Array2<f64>) -> Vec<f64> {
        let n_features = data.ncols();
        let mut importance = vec![0.0; n_features];

        for tree in &self.trees {
            tree.compute_feature_importance(&mut importance);
        }

        let total: f64 = importance.iter().sum();
        importance.iter_mut().for_each(|i| *i /= total);
        importance
    }
}

impl IsolationTree {
    fn build(data: Array2<f64>, height: u32, rng: &mut ChaCha8Rng) -> Self {
        if data.nrows() <= 1 || height >= 100 {
            return IsolationTree { root: None };
        }

        let n_features = data.ncols();
        let split_attr = rng.gen_range(0..n_features);
        let min = data.column(split_attr).min().unwrap();
        let max = data.column(split_attr).max().unwrap();
        let split_value = rng.gen_range(min..=max);

        let (left_data, right_data): (Vec<_>, Vec<_>) = data.outer_iter()
            .partition(|row| row[split_attr] < split_value);

        let left_data = Array2::from_shape_vec((left_data.len(), n_features), left_data.into_iter().flatten().cloned().collect()).unwrap();
        let right_data = Array2::from_shape_vec((right_data.len(), n_features), right_data.into_iter().flatten().cloned().collect()).unwrap();

        let left = IsolationTree::build(left_data, height + 1, rng);
        let right = IsolationTree::build(right_data, height + 1, rng);

        IsolationTree {
            root: Some(Box::new(TreeNode {
                split_attr,
                split_value,
                left: left.root,
                right: right.root,
                height,
            })),
        }
    }

    fn path_length(&self, instance: &ArrayView1<f64>) -> u32 {
        match &self.root {
            Some(node) => node.path_length(instance),
            None => 0,
        }
    }
}

impl TreeNode {
    fn path_length(&self, instance: &ArrayView1<f64>) -> u32 {
        match instance[self.split_attr].partial_cmp(&self.split_value) {
            Some(Ordering::Less) => {
                match &self.left {
                    Some(left) => left.path_length(instance),
                    None => self.height + 1,
                }
            }
            _ => {
                match &self.right {
                    Some(right) => right.path_length(instance),
                    None => self.height + 1,
                }
            }
        }
    }

    fn compute_feature_importance(&self, importance: &mut Vec<f64>) {
        importance[self.split_attr] += 1.0;
        if let Some(left) = &self.left {
            left.compute_feature_importance(importance);
        }
        if let Some(right) = &self.right {
            right.compute_feature_importance(importance);
        }
    }
}

pub struct MLModel {
    model: IsolationForest,
    threshold: f64,
    feature_importance: Vec<f64>,
}

impl MLModel {
    pub fn new(n_trees: usize, sample_size: usize, threshold: f64) -> Self {
        MLModel {
            model: IsolationForest::new(n_trees, sample_size),
            threshold,
            feature_importance: Vec::new(),
        }
    }

    pub fn train(&mut self, data: &Array2<f64>) {
        self.model.fit(data);
        self.feature_importance = self.model.compute_feature_importance(data);
    }

    pub fn predict(&self, instance: &ArrayView1<f64>) -> bool {
        let anomaly_score = self.model.predict(&instance.to_owned());
        anomaly_score > self.threshold
    }

    pub fn cross_validate(&mut self, data: &Array2<f64>, n_folds: usize) -> f64 {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut indices: Vec<usize> = (0..data.nrows()).collect();
        indices.shuffle(&mut rng);

        let fold_size = data.nrows() / n_folds;
        let mut scores = Vec::new();

        for i in 0..n_folds {
            let test_start = i * fold_size;
            let test_end = if i == n_folds - 1 { data.nrows() } else { (i + 1) * fold_size };

            let train_data = Array2::from_shape_vec(
                (data.nrows() - (test_end - test_start), data.ncols()),
                indices.iter()
                    .filter(|&&idx| idx < test_start || idx >= test_end)
                    .flat_map(|&idx| data.row(idx).to_vec())
                    .collect(),
            ).unwrap();

            let test_data = Array2::from_shape_vec(
                (test_end - test_start, data.ncols()),
                indices[test_start..test_end].iter()
                    .flat_map(|&idx| data.row(idx).to_vec())
                    .collect(),
            ).unwrap();

            self.train(&train_data);

            let score = test_data.outer_iter()
                .map(|instance| self.predict(&instance) as u32)
                .sum::<u32>() as f64 / test_data.nrows() as f64;

            scores.push(score);
        }

        scores.iter().sum::<f64>() / n_folds as f64
    }

    pub fn get_feature_importance(&self) -> &Vec<f64> {
        &self.feature_importance
    }
}

pub fn engineer_features(stats: &[f64]) -> Array1<f64> {
    let packet_count = stats[0];
    let byte_count = stats[1];
    let tcp_count = stats[2];
    let udp_count = stats[3];
    let icmp_count = stats[4];
    let http_count = stats[5];
    let https_count = stats[6];

    let total_count = tcp_count + udp_count + icmp_count;

    Array1::from(vec![
        packet_count,
        byte_count,
        tcp_count,
        udp_count,
        icmp_count,
        http_count,
        https_count,
        byte_count / packet_count.max(1.0),  // Average packet size
        tcp_count / total_count.max(1.0),    // TCP ratio
        udp_count / total_count.max(1.0),    // UDP ratio
        icmp_count / total_count.max(1.0),   // ICMP ratio
        (http_count + https_count) / total_count.max(1.0),  // HTTP(S) ratio
        (packet_count - tcp_count - udp_count - icmp_count).max(0.0) / packet_count.max(1.0),  // Unknown protocol ratio
    ])
}