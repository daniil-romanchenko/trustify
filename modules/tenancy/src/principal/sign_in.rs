//! Linking authenticated OIDC identities to users.

use crate::{
    Error,
    audit::{self, Actor, Change},
    email::normalize_email,
    user::model::UserState,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, Set,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use trustify_common::db::DatabaseErrors;
use trustify_entity::principal_user;
use uuid::Uuid;

/// An authenticated identity, as provided by the OIDC access token.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    /// The verified e-mail address.
    pub email: String,
}

/// The outcome of signing in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignIn {
    /// The identity is linked to this user.
    User(principal_user::Model),
    /// There is no user for this identity, and none was created.
    Unknown,
    /// The e-mail address belongs to a user linked to a different identity.
    Conflict,
}

/// Find the user linked to an identity, without making any changes.
///
/// This is used when the database is read-only. It falls back to users provisioned by e-mail,
/// which are not linked yet.
pub async fn find_linked(identity: &Identity, db: &impl ConnectionTrait) -> Result<SignIn, Error> {
    if let Some(user) = principal_user::Entity::find()
        .filter(principal_user::Column::OidcIssuer.eq(&identity.issuer))
        .filter(principal_user::Column::OidcSub.eq(&identity.subject))
        .one(db)
        .await?
    {
        return Ok(SignIn::User(user));
    }

    let email = normalize_email(&identity.email)?;
    Ok(
        match principal_user::Entity::find()
            .filter(principal_user::Column::Email.eq(email))
            .one(db)
            .await?
        {
            Some(user) if user.oidc_sub.is_none() => SignIn::User(user),
            Some(_) => SignIn::Conflict,
            None => SignIn::Unknown,
        },
    )
}

/// Link an identity to a user, creating the user if requested.
///
/// The identity is first looked up by issuer and subject. If it isn't linked yet, a user with
/// a matching e-mail address, not yet linked to any identity, gets linked. Otherwise, a new user
/// is created when `just_in_time` is `true`.
///
/// This should be called in a transaction.
pub async fn sign_in(
    identity: &Identity,
    just_in_time: bool,
    db: &impl ConnectionTrait,
) -> Result<SignIn, Error> {
    let email = normalize_email(&identity.email)?;
    let now = OffsetDateTime::now_utc();

    // already linked

    if let Some(user) = principal_user::Entity::find()
        .filter(principal_user::Column::OidcIssuer.eq(&identity.issuer))
        .filter(principal_user::Column::OidcSub.eq(&identity.subject))
        .lock_exclusive()
        .one(db)
        .await?
    {
        let previous_email = user.email.clone();
        let mut model = user.into_active_model();
        model.last_login = Set(Some(now));

        if previous_email != email {
            // the identity provider changed the address, follow if it's not taken
            let taken = principal_user::Entity::find()
                .filter(principal_user::Column::Email.eq(&email))
                .one(db)
                .await?
                .is_some();

            if taken {
                log::warn!(
                    "Not updating e-mail of user linked to '{}' / '{}' from '{previous_email}' to '{email}': address is in use",
                    identity.issuer,
                    identity.subject,
                );
            } else {
                model.email = Set(email.clone());
                model.revision = Set(Uuid::now_v7());
            }
        }

        let user = model.update(db).await?;

        if user.email != previous_email {
            record(
                "change-email",
                &user,
                json!({"from": previous_email, "to": user.email}),
                db,
            )
            .await?;
        }

        return Ok(SignIn::User(user));
    }

    // provisioned by e-mail

    if let Some(user) = principal_user::Entity::find()
        .filter(principal_user::Column::Email.eq(&email))
        .lock_exclusive()
        .one(db)
        .await?
    {
        if user.oidc_sub.is_some() {
            log::warn!(
                "User '{email}' is linked to a different identity than '{}' / '{}'",
                identity.issuer,
                identity.subject
            );
            return Ok(SignIn::Conflict);
        }

        let mut model = user.into_active_model();
        model.oidc_issuer = Set(Some(identity.issuer.clone()));
        model.oidc_sub = Set(Some(identity.subject.clone()));
        model.last_login = Set(Some(now));
        model.revision = Set(Uuid::now_v7());
        if model.state.as_ref() == &UserState::Invited {
            model.state = Set(UserState::Active);
        }

        let user = model.update(db).await?;
        record("link", &user, json!({}), db).await?;

        return Ok(SignIn::User(user));
    }

    // unknown

    if !just_in_time {
        return Ok(SignIn::Unknown);
    }

    let user = principal_user::ActiveModel {
        id: Set(Uuid::now_v7()),
        email: Set(email),
        oidc_issuer: Set(Some(identity.issuer.clone())),
        oidc_sub: Set(Some(identity.subject.clone())),
        display_name: Set(None),
        external_id: Set(None),
        state: Set(UserState::Active),
        created_at: Set(now),
        last_login: Set(Some(now)),
        revision: Set(Uuid::now_v7()),
    }
    .insert(db)
    .await
    .map_err(|err| {
        if err.is_duplicate() {
            // a concurrent sign-in created it, the caller may retry
            Error::Conflict("User was created concurrently".into())
        } else {
            err.into()
        }
    })?;

    record("create", &user, json!({"justInTime": true}), db).await?;

    Ok(SignIn::User(user))
}

async fn record(
    action: &'static str,
    user: &principal_user::Model,
    mut detail: Value,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    if let Some(detail) = detail.as_object_mut() {
        detail.insert("email".into(), json!(user.email));
        detail.insert("issuer".into(), json!(user.oidc_issuer));
        detail.insert("subject".into(), json!(user.oidc_sub));
    }

    let actor = Actor {
        kind: "user",
        id: user.oidc_sub.clone().unwrap_or_default(),
    };

    audit::record(
        &actor,
        Change {
            action,
            target_kind: "user",
            target_id: &user.id.to_string(),
            detail,
        },
        db,
    )
    .await?;

    Ok(())
}
