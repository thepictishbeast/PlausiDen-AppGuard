//! Pre-built sandbox profiles for common application types.

use serde::{Deserialize, Serialize};

/// A pre-defined sandbox profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileTemplate {
    pub name: String,
    pub description: String,
    pub allow_network: bool,
    pub allow_filesystem_read: Vec<String>,
    pub allow_filesystem_write: Vec<String>,
    pub deny_filesystem: Vec<String>,
    pub allow_dbus: bool,
    pub allow_x11: bool,
    pub allow_audio: bool,
    pub allow_camera: bool,
    pub allow_microphone: bool,
}

/// Pre-built profile registry.
pub struct ProfileRegistry {
    profiles: Vec<ProfileTemplate>,
}

impl ProfileRegistry {
    pub fn new() -> Self {
        Self {
            profiles: Self::build_defaults(),
        }
    }

    fn build_defaults() -> Vec<ProfileTemplate> {
        vec![
            ProfileTemplate {
                name: "web-browser".into(),
                description: "Web browser with network and limited filesystem access".into(),
                allow_network: true,
                allow_filesystem_read: vec!["~/Downloads".into(), "~/.config/firefox".into()],
                allow_filesystem_write: vec!["~/Downloads".into(), "~/.cache/firefox".into()],
                deny_filesystem: vec!["~/.ssh".into(), "~/.gnupg".into(), "/etc".into()],
                allow_dbus: true,
                allow_x11: true,
                allow_audio: true,
                allow_camera: false,
                allow_microphone: false,
            },
            ProfileTemplate {
                name: "text-editor".into(),
                description: "Text/code editor with no network".into(),
                allow_network: false,
                allow_filesystem_read: vec!["~".into()],
                allow_filesystem_write: vec!["~".into()],
                deny_filesystem: vec!["~/.ssh".into(), "~/.gnupg".into(), "/etc".into()],
                allow_dbus: true,
                allow_x11: true,
                allow_audio: false,
                allow_camera: false,
                allow_microphone: false,
            },
            ProfileTemplate {
                name: "media-player".into(),
                description: "Media player with audio and limited network".into(),
                allow_network: true,
                allow_filesystem_read: vec!["~/Music".into(), "~/Videos".into(), "~/Downloads".into()],
                allow_filesystem_write: vec![],
                deny_filesystem: vec!["~".into()],
                allow_dbus: true,
                allow_x11: true,
                allow_audio: true,
                allow_camera: false,
                allow_microphone: false,
            },
            ProfileTemplate {
                name: "communication".into(),
                description: "Chat/video app with camera, mic, network".into(),
                allow_network: true,
                allow_filesystem_read: vec!["~/Downloads".into(), "~/Pictures".into()],
                allow_filesystem_write: vec!["~/Downloads".into()],
                deny_filesystem: vec!["~/.ssh".into(), "/etc".into()],
                allow_dbus: true,
                allow_x11: true,
                allow_audio: true,
                allow_camera: true,
                allow_microphone: true,
            },
            ProfileTemplate {
                name: "development".into(),
                description: "IDE/dev tool with network and full home access".into(),
                allow_network: true,
                allow_filesystem_read: vec!["~".into(), "/usr".into()],
                allow_filesystem_write: vec!["~".into(), "/tmp".into()],
                deny_filesystem: vec!["/etc/shadow".into(), "/root".into()],
                allow_dbus: true,
                allow_x11: true,
                allow_audio: false,
                allow_camera: false,
                allow_microphone: false,
            },
            ProfileTemplate {
                name: "untrusted".into(),
                description: "Maximum lockdown for untrusted apps".into(),
                allow_network: false,
                allow_filesystem_read: vec![],
                allow_filesystem_write: vec![],
                deny_filesystem: vec!["/".into()],
                allow_dbus: false,
                allow_x11: false,
                allow_audio: false,
                allow_camera: false,
                allow_microphone: false,
            },
        ]
    }

    /// Get profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileTemplate> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Add a custom profile.
    pub fn add(&mut self, profile: ProfileTemplate) {
        self.profiles.push(profile);
    }

    /// List all profiles.
    pub fn list(&self) -> &[ProfileTemplate] {
        &self.profiles
    }

    pub fn count(&self) -> usize { self.profiles.len() }
}

impl Default for ProfileRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profiles() {
        let reg = ProfileRegistry::new();
        assert!(reg.count() >= 6);
    }

    #[test]
    fn test_get_browser_profile() {
        let reg = ProfileRegistry::new();
        let p = reg.get("web-browser").unwrap();
        assert!(p.allow_network);
        assert!(p.allow_x11);
        assert!(!p.allow_camera);
    }

    #[test]
    fn test_text_editor_no_network() {
        let reg = ProfileRegistry::new();
        let p = reg.get("text-editor").unwrap();
        assert!(!p.allow_network);
    }

    #[test]
    fn test_communication_full_access() {
        let reg = ProfileRegistry::new();
        let p = reg.get("communication").unwrap();
        assert!(p.allow_camera);
        assert!(p.allow_microphone);
    }

    #[test]
    fn test_untrusted_lockdown() {
        let reg = ProfileRegistry::new();
        let p = reg.get("untrusted").unwrap();
        assert!(!p.allow_network);
        assert!(!p.allow_dbus);
        assert!(p.allow_filesystem_read.is_empty());
    }

    #[test]
    fn test_add_custom() {
        let mut reg = ProfileRegistry::new();
        let count = reg.count();
        reg.add(ProfileTemplate {
            name: "custom".into(),
            description: "test".into(),
            allow_network: false,
            allow_filesystem_read: vec![],
            allow_filesystem_write: vec![],
            deny_filesystem: vec![],
            allow_dbus: false,
            allow_x11: false,
            allow_audio: false,
            allow_camera: false,
            allow_microphone: false,
        });
        assert_eq!(reg.count(), count + 1);
    }
}
