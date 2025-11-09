pub mod connection_ids {
    pub const BEDROCK_ACCOUNT: &str = "bv:bedrock_link";
    pub const MOJANG_UUID: &str = "bv:mojang_uuid";
    pub const PLAYTIME: &str = "bv:playtime";
}

pub mod api_scopes {
    pub const SERVER_READ: &str = "servers.read";
    pub const SERVER_SELF_MODIFY: &str = "servers.self.modify";
    pub const PROFILE_READ: &str = "profiles.read";
    pub const PROFILE_CREATE: &str = "profiles.create";
    pub const PROFILE_OTHERS_MODIFY: &str = "profiles.others.modify";
    pub const PROFILE_SELF_MODIFY: &str = "profiles.self.modify";
}

pub mod session {
    use chrono::TimeDelta;

    pub const LEASE_TIME: TimeDelta = TimeDelta::minutes(10);
}

pub mod cidr {
    pub const MIN_V4_MASK: u8 = 16;
}
