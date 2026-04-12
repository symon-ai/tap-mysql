#!/usr/bin/env python3

import unittest
import ssl
from unittest.mock import patch, MagicMock
from tap_mysql.connection import MySQLConnection


class TestSSLConfiguration(unittest.TestCase):
    """Test SSL/TLS configuration to ensure secure protocol usage (CWE-757)"""

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_ssl_minimum_tls_version_set(self, mock_connect):
        """Test that minimum TLS version is set to TLS 1.2 when SSL is enabled without custom CA"""
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'verify_mode': 'true'
        }

        connection = MySQLConnection(config)

        self.assertTrue(hasattr(connection, 'ctx'))
        self.assertIsNotNone(connection.ctx)
        self.assertEqual(connection.ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_ssl_context_created_when_ssl_enabled(self, mock_connect):
        """Test that SSL context is properly created when SSL is enabled"""
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true'
        }

        connection = MySQLConnection(config)

        self.assertTrue(hasattr(connection, 'ctx'))
        self.assertIsNotNone(connection.ctx)
        self.assertIsInstance(connection.ctx, ssl.SSLContext)

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_ssl_verify_mode_when_enabled(self, mock_connect):
        """Test that SSL verify mode is set to CERT_REQUIRED when verify_mode is true"""
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'verify_mode': 'true'
        }

        connection = MySQLConnection(config)

        self.assertEqual(connection.ctx.verify_mode, ssl.CERT_REQUIRED)

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_ssl_verify_mode_when_disabled(self, mock_connect):
        """Test that SSL verify mode is set to CERT_NONE when verify_mode is false"""
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'verify_mode': 'false'
        }

        connection = MySQLConnection(config)

        self.assertEqual(connection.ctx.verify_mode, ssl.CERT_NONE)

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_check_hostname_configuration(self, mock_connect):
        """Test that check_hostname is properly configured"""
        config_with_check = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'check_hostname': 'true',
            'verify_mode': 'true'
        }

        connection_with_check = MySQLConnection(config_with_check)
        self.assertTrue(connection_with_check.ctx.check_hostname)

        config_without_check = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'check_hostname': 'false'
        }

        connection_without_check = MySQLConnection(config_without_check)
        self.assertFalse(connection_without_check.ctx.check_hostname)

    @patch('tap_mysql.connection.connect_with_backoff')
    def test_no_ssl_context_when_ssl_disabled(self, mock_connect):
        """Test that SSL context is not created when SSL is disabled"""
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password'
        }

        connection = MySQLConnection(config)

        self.assertFalse(hasattr(connection, 'ctx') and connection.ctx is not None)

    @patch('tap_mysql.connection.connect_with_backoff')
    @patch('pymysql.connections.Connection.__init__')
    def test_ssl_with_custom_ca(self, mock_pymysql_init, mock_connect):
        """Test that custom CA configuration is passed correctly"""
        # Mock the parent __init__ to avoid SSL certificate validation
        mock_pymysql_init.return_value = None
        
        config = {
            'host': 'test-host',
            'port': 3306,
            'user': 'test-user',
            'password': 'test-password',
            'ssl': 'true',
            'ssl_ca': '/path/to/ca.pem'
        }

        # This should not raise an error and should pass ssl_ca to the ssl_arg
        connection = MySQLConnection(config)
        
        # Verify that __init__ was called with ssl parameter containing ca
        self.assertTrue(mock_pymysql_init.called)
        call_kwargs = mock_pymysql_init.call_args[1]
        self.assertIn('ssl', call_kwargs)
        self.assertIsNotNone(call_kwargs['ssl'])
        self.assertEqual(call_kwargs['ssl']['ca'], '/path/to/ca.pem')


if __name__ == '__main__':
    unittest.main()
