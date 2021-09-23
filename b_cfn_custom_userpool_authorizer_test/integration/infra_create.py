import os

from b_cfn_custom_userpool_authorizer_test.integration.manager import MANAGER

DO_NOT_CREATE_INFRASTRUCTURE = int(os.environ.get('DO_NOT_CREATE_INFRASTRUCTURE', 0))


def inf_create():
    if DO_NOT_CREATE_INFRASTRUCTURE == 1:
        return

    MANAGER.prepare_infrastructure()


if __name__ == '__main__':
    inf_create()
