use crate::{
    api_key::{config::TenancyConfig, service::ApiKeyService, validator::ApiKeyValidator},
    binding::service::BindingService,
    principal::PrincipalResolver,
    team::service::TeamService,
    user::service::UserService,
};
use actix_web::web;
use std::sync::Arc;
use trustify_auth::authenticator::token::TokenValidator;
use trustify_common::db::{self, pagination_cache::PaginationCache};

/// Shared state of the tenancy module, also used by middleware outside of it.
#[derive(Clone)]
pub struct Tenancy {
    pub resolver: Arc<PrincipalResolver>,
    pub api_keys: ApiKeyService,
    pub api_key_validator: Arc<ApiKeyValidator>,
}

impl Tenancy {
    pub fn new(config: &TenancyConfig, db_rw: db::ReadWrite, cache: PaginationCache) -> Self {
        let api_keys = ApiKeyService::new(config, cache);
        Self {
            resolver: Arc::new(PrincipalResolver::new(
                db_rw.clone(),
                !config.no_just_in_time_users,
            )),
            api_key_validator: Arc::new(ApiKeyValidator::new(api_keys.clone(), db_rw)),
            api_keys,
        }
    }

    /// Validators for additional bearer tokens, to be registered with the authenticator.
    pub fn token_validators(&self) -> Vec<Arc<dyn TokenValidator>> {
        if self.api_keys.enabled() {
            vec![self.api_key_validator.clone()]
        } else {
            vec![]
        }
    }
}

/// Mount the "tenancy" module
pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    cache: PaginationCache,
    tenancy: Tenancy,
) {
    config
        .app_data(web::Data::from(tenancy.resolver))
        .app_data(web::Data::from(tenancy.api_key_validator))
        .app_data(web::Data::new(tenancy.api_keys))
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(UserService::new(cache.clone())))
        .app_data(web::Data::new(TeamService::new(cache)))
        .app_data(web::Data::new(BindingService::new()))
        .configure(crate::user::endpoints::configure)
        .configure(crate::team::endpoints::configure)
        .configure(crate::binding::endpoints::configure)
        .configure(crate::api_key::endpoints::configure)
        .configure(crate::me::configure);
}
