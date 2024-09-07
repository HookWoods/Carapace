use std::collections::HashMap;
use std::net::Ipv4Addr;
use aya::maps::MapData;

pub struct BlacklistEntry {
    blacklist_time: u64,
    offense_count: u32,
}

pub struct BlacklistManager {
    blacklist: HashMap<u32, BlacklistEntry>,
    temp_blacklist_duration: u64,
    max_offenses: u32,
}

impl BlacklistManager {
    pub fn new(temp_blacklist_duration: u64, max_offenses: u32) -> Self {
        Self {
            blacklist: HashMap::new(),
            temp_blacklist_duration,
            max_offenses,
        }
    }

    pub fn add_to_blacklist(&mut self, ip: u32, now: u64) -> bool {
        let entry = self.blacklist.entry(ip).or_insert(BlacklistEntry {
            blacklist_time: now,
            offense_count: 0,
        });

        entry.blacklist_time = now;
        entry.offense_count += 1;

        entry.offense_count >= self.max_offenses
    }

    pub fn is_blacklisted(&self, ip: u32, now: u64) -> bool {
        if let Some(entry) = self.blacklist.get(&ip) {
            now - entry.blacklist_time < self.temp_blacklist_duration
        } else {
            false
        }
    }

    pub fn remove_expired(&mut self, now: u64) {
        self.blacklist.retain(|_, entry| {
            now - entry.blacklist_time < self.temp_blacklist_duration
        });
    }
}

pub async fn cleanup_blacklist(blacklist_manager: &mut BlacklistManager, blacklist_map: &mut aya::maps::HashMap<MapData, u32, u8>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    blacklist_manager.remove_expired(now);

    let mut to_remove = Vec::new();

    let mut iter = blacklist_map.iter();
    while let Some(Ok((ip, _))) = iter.next() {
        if !blacklist_manager.is_blacklisted(ip, now) {
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