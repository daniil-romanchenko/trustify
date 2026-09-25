use crate::{
    binding::service::BindingService, principal::PrincipalResolver, team::service::TeamService,
    user::service::UserService,
};
use actix_web::web;
use std::sync::Arc;
use trustify_common::db::{self, pagination_cache::PaginationCache};

/// Mount the "tenancy" module
pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    cache: PaginationCache,
    resolver: Arc<PrincipalResolver>,
) {
    config
        .app_data(web::Data::from(resolver))
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(UserService::new(cache.clone())))
        .app_data(web::Data::new(TeamService::new(cache)))
        .app_data(web::Data::new(BindingService::new()))
        .configure(crate::user::endpoints::configure)
        .configure(crate::team::endpoints::configure)
        .configure(crate::binding::endpoints::configure)
        .configure(crate::me::configure);
}
