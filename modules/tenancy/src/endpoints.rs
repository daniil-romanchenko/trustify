use crate::{
    binding::service::BindingService, team::service::TeamService, user::service::UserService,
};
use actix_web::web;
use trustify_common::db::{self, pagination_cache::PaginationCache};

/// Mount the "tenancy" module
pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    cache: PaginationCache,
) {
    config
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(UserService::new(cache.clone())))
        .app_data(web::Data::new(TeamService::new(cache)))
        .app_data(web::Data::new(BindingService::new()))
        .configure(crate::user::endpoints::configure)
        .configure(crate::team::endpoints::configure)
        .configure(crate::binding::endpoints::configure);
}
