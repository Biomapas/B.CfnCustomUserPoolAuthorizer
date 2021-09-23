# Import all the fixtures.
# noinspection PyUnresolvedReferences
from b_cfn_custom_userpool_authorizer_test.integration.fixtures import *

from b_cfn_custom_userpool_authorizer_test.integration.infra_create import inf_create
from b_cfn_custom_userpool_authorizer_test.integration.infra_destroy import inf_destroy


def pytest_sessionstart(session):
    inf_create()


def pytest_sessionfinish(session, exitstatus):
    inf_destroy()
