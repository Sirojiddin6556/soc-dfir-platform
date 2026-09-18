use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Lead,
    Analyst,
    Responder,
    Viewer,
    CtfParticipant,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Lead => "Lead",
            Self::Analyst => "Analyst",
            Self::Responder => "Responder",
            Self::Viewer => "Viewer",
            Self::CtfParticipant => "CtfParticipant",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "lead" => Self::Lead,
            "analyst" => Self::Analyst,
            "responder" => Self::Responder,
            "ctfparticipant" | "ctf_participant" => Self::CtfParticipant,
            _ => Self::Viewer,
        }
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => perm != Permission::CtfIsolatedOnly,
            Self::Lead => !matches!(
                perm,
                Permission::WorkspaceManage
                    | Permission::MemberRemove
                    | Permission::CtfIsolatedOnly
            ),
            Self::Analyst => matches!(
                perm,
                Permission::CaseRead
                    | Permission::EvidenceRead
                    | Permission::EvidenceAdd
                    | Permission::FindingCreate
                    | Permission::FindingConfirm
                    | Permission::ChatRead
                    | Permission::ChatWrite
            ),
            Self::Responder => matches!(
                perm,
                Permission::CaseRead
                    | Permission::EvidenceRead
                    | Permission::FindingCreate
                    | Permission::ChatRead
                    | Permission::ChatWrite
            ),
            Self::Viewer => matches!(
                perm,
                Permission::CaseRead | Permission::EvidenceRead | Permission::ChatRead
            ),
            Self::CtfParticipant => matches!(
                perm,
                Permission::CtfIsolatedOnly | Permission::ChatRead | Permission::ChatWrite
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    CaseRead,
    CaseCreate,
    CaseUpdate,
    CaseClose,
    EvidenceRead,
    EvidenceAdd,
    EvidenceExport,
    FindingCreate,
    FindingConfirm,
    FindingDelete,
    GraphEdit,
    ChatRead,
    ChatWrite,
    MemberInvite,
    MemberRemove,
    WorkspaceManage,
    CtfIsolatedOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: EntityId,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: Role,
    pub department: String,
    pub timezone: String,
    pub language: String,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: EntityId,
    pub username: String,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: EntityId,
    pub name: String,
    pub organization_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: EntityId,
    pub workspace_id: EntityId,
    pub name: String,
    pub description: String,
    pub member_count: usize,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub team_id: EntityId,
    pub user_id: EntityId,
    pub username: String,
    pub display_name: String,
    pub role: Role,
    pub is_online: bool,
    pub current_action: Option<String>,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    General,
    Team,
    Case,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: EntityId,
    pub workspace_id: EntityId,
    pub case_id: Option<EntityId>,
    pub name: String,
    pub channel_type: ChannelType,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceType {
    Finding,
    Evidence,
    Asset,
    Process,
    Cve,
    Mitre,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRef {
    pub ref_type: ReferenceType,
    pub ref_id: String,
    pub title: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: EntityId,
    pub channel_id: EntityId,
    pub author_id: EntityId,
    pub author_name: String,
    pub author_role: Role,
    pub body: String,
    pub reply_to_id: Option<EntityId>,
    pub references: Vec<EntityRef>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPresence {
    pub user_id: EntityId,
    pub username: String,
    pub display_name: String,
    pub is_online: bool,
    pub active_case_id: Option<String>,
    pub status_text: String,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabNotification {
    pub id: EntityId,
    pub user_id: EntityId,
    pub title: String,
    pub body: String,
    pub category: String,
    pub is_read: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OperationMode {
    #[default]
    Live,
    Demo,
    Ctf,
}

impl OperationMode {
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }

    pub fn is_synthetic_allowed(&self) -> bool {
        matches!(self, Self::Demo | Self::Ctf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
    Left,
    Removed,
}

impl MembershipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Invited => "Invited",
            Self::Active => "Active",
            Self::Suspended => "Suspended",
            Self::Left => "Left",
            Self::Removed => "Removed",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "invited" => Self::Invited,
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "left" => Self::Left,
            "removed" => Self::Removed,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Revoked,
}

impl InvitationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Accepted => "Accepted",
            Self::Declined => "Declined",
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "declined" => Self::Declined,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub workspace_id: EntityId,
    pub user_id: EntityId,
    pub role: Role,
    pub status: MembershipStatus,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: EntityId,
    pub workspace_id: EntityId,
    pub team_id: Option<EntityId>,
    pub code: String,
    pub token_hash: String,
    pub created_by: EntityId,
    pub email: Option<String>,
    pub role: Role,
    pub expires_at: DateTime<Utc>,
    pub max_uses: usize,
    pub used_count: usize,
    pub status: InvitationStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMember {
    pub case_id: EntityId,
    pub user_id: EntityId,
    pub role: Role,
    pub assigned_by: EntityId,
    pub assigned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl JoinRequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Rejected => "Rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub id: EntityId,
    pub workspace_id: EntityId,
    pub team_id: Option<EntityId>,
    pub user_id: EntityId,
    pub role: Role,
    pub status: JoinRequestStatus,
    pub reviewed_by: Option<EntityId>,
    pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipAuditEntry {
    pub id: EntityId,
    pub workspace_id: EntityId,
    pub user_id: EntityId,
    pub actor_id: EntityId,
    pub action: String,
    pub details: String,
    pub created_at: DateTime<Utc>,
}
