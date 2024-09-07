pub struct DynamicThreshold {
    pub base: u32,
    multiplier: f32,
    max: u32,
}

impl DynamicThreshold {
    pub fn new(base: u32, multiplier: f32, max: u32) -> Self {
        Self { base, multiplier, max }
    }

    pub fn calculate(&self, current: u32) -> u32 {
        std::cmp::min((current as f32 * self.multiplier) as u32 + self.base, self.max)
    }
}