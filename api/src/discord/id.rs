use std::{fmt::Display, str::FromStr};

pub struct Id {
    pub action: Action,
    pub nonce: String,
    pub target: Option<String>,
}

impl Id {
    // Its just `action:nonce@target`.
    pub fn encode(id: &Self) -> Option<String> {
        let mut it = format!("{}:{}", id.action, id.nonce);

        if let Some(target) = id.target.clone() {
            it = format!("{}@{}", it, target);
        }

        if it.len() > 100 {
            None
        } else {
            Some(it)
        }
    }

    pub fn decode(s: &str) -> Option<Self> {
        let str_arr: Vec<_> = s.split(":").collect();

        if str_arr.len() < 2 {
            return None;
        }

        let (fst, snd) = (str_arr.first()?, str_arr.get(1)?);

        let (target, nonce) = if snd.contains("@") {
            let nonce_arr: Vec<_> = snd.split("@").collect();
            (
                Some(nonce_arr.last().cloned()?.to_string()),
                nonce_arr.first().cloned()?.to_string(),
            )
        } else {
            (None, snd.to_string())
        };

        let action: Action = fst.parse().ok()?;

        Some(Self { action, nonce, target })
    }
}

pub enum Action {
    AcceptIp,
    DenyIp,
    PasswordInput,
    PromptBanIp,
    ReturnIp,
}

impl FromStr for Action {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "b#ip_a" => Ok(Self::AcceptIp),
            "b#ip_d" => Ok(Self::DenyIp),
            "b#ip_p" => Ok(Self::PromptBanIp),
            "b#ip_r" => Ok(Self::ReturnIp),
            "t#pass" => Ok(Self::PasswordInput),
            _ => Err(()),
        }
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptIp => write!(f, "b#ip_a"),
            Self::DenyIp => write!(f, "b#ip_d"),
            Self::PromptBanIp => write!(f, "b#ip_p"),
            Self::ReturnIp => write!(f, "b#ip_r"),
            Self::PasswordInput => write!(f, "t#pass"),
        }
    }
}
