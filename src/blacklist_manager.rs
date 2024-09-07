use std::collections::HashMap;
use std::net::Ipv4Addr;
use aya::maps::MapData;

pub struct BlacklistEntry {
    blacklist_time: u64,
    offense_count: u32,
}

pub struct BlacklistConfig {
    pub temp_blacklist_duration: u64,
    pub max_offenses: u32,
}

pub struct BlacklistManager {
    blacklist: HashMap<u32, BlacklistEntry>,
    blacklist_config: BlacklistConfig,
}


impl BlacklistManager {
    pub fn new(blacklist_config: BlacklistConfig) -> Self {
        Self {
            blacklist: HashMap::new(),
            blacklist_config
        }
    }

    pub fn add_to_blacklist(&mut self, ip: u32, now: u64) -> bool {
        let entry = self.blacklist.entry(ip).or_insert(BlacklistEntry {
            blacklist_time: now,
            offense_count: 0,
        });

        entry.blacklist_time = now;
        entry.offense_count += 1;

        entry.offense_count >= *self.blacklist_config.max_offenses
    }

    pub fn is_blacklisted(&self, ip: u32, now: u64) -> bool {
        if let Some(entry) = self.blacklist.get(&ip) {
            now - entry.blacklist_time < *self.blacklist_config.temp_blacklist_duration
        } else {
            false
        }
    }

    pub fn remove_expired(&mut self, now: u64) {
        self.blacklist.retain(|_, entry| {
            now - entry.blacklist_time < *self.blacklist_config.temp_blacklist_duration
        });
    }

    pub async fn cleanup_blacklist(&mut self, blacklist_map: &mut aya::maps::HashMap<MapData, u32, u8>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.remove_expired(now);

        let mut to_remove = Vec::new();

        let mut iter = blacklist_map.iter();
        while let Some(Ok((ip, _))) = iter.next() {
            if !self.is_blacklisted(ip, now) {
                to_remove.push(ip);
            }
        }

        for ip in to_remove {
            if let Err(e) = blacklist_map.remove(&ip) {
                println!("Failed to remove IP {} from blacklist: {:?}", Ipv4Addr::from(ip), e);
            } else {
                println!("Removed IP {} from blacklist", Ipv4Addr::from(ip));
            }
        }
    }
}