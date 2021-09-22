from b_cfn_custom_userpool_authorizer_test.integration.infra_create import inf_create
from b_cfn_custom_userpool_authorizer_test.integration.infra_destroy import inf_destroy
from b_cfn_custom_userpool_authorizer_test.integration.manager import MANAGER


def pytest_sessionstart(session):
    MANAGER.set_global_prefix('Laimonas', override=True)
    inf_create()


def pytest_sessionfinish(session, exitstatus):
    MANAGER.set_global_prefix('Laimonas', override=True)
    # inf_destroy()
