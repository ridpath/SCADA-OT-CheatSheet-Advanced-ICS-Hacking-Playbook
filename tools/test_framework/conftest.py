"""
pytest configuration and fixtures
"""

import sys
from unittest.mock import MagicMock


def pytest_configure(config):
    """Configure pytest environment"""
    
    sys.modules['scapy.layers.dnp3'] = MagicMock()
    
    DNP3_mock = MagicMock()
    DNP3_mock.DNP3 = MagicMock()
    sys.modules['scapy.layers.dnp3'] = DNP3_mock
    
    sys.modules['snap7'] = MagicMock()
    sys.modules['snap7.util'] = MagicMock()
    sys.modules['snap7.types'] = MagicMock()
    sys.modules['argcomplete'] = MagicMock()
    
    pycomm3_mock = MagicMock()
    pycomm3_mock.LogixDriver = MagicMock()
    pycomm3_mock.CIPDriver = MagicMock()
    pycomm3_mock.Services = MagicMock()
    sys.modules['pycomm3'] = pycomm3_mock
    
    pycomm3_exceptions_mock = MagicMock()
    pycomm3_exceptions_mock.CommError = Exception
    pycomm3_exceptions_mock.RequestError = Exception
    pycomm3_exceptions_mock.PyCommError = Exception
    sys.modules['pycomm3.exceptions'] = pycomm3_exceptions_mock
    
    sys.modules['asyncua'] = MagicMock()
    sys.modules['asyncua.common'] = MagicMock()
    sys.modules['asyncua.common.node'] = MagicMock()
    sys.modules['asyncua.crypto'] = MagicMock()
    sys.modules['asyncua.ua'] = MagicMock()
    sys.modules['asyncua.ua.uaerrors'] = MagicMock()
