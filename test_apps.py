import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from quantumapp.models import Node
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from quantumapp.apps import QuantumappConfig
import logging

logger = logging.getLogger(__name__)

@pytest.mark.django_db
def test_node_registration():
    client = APIClient()

    logger.info("Creating a user to act as the master node owner...")
    master_node_user = User.objects.create_user(username='master', password='masterpass')

    logger.info("Simulating registering the master node...")
    response = client.post(reverse('register_node'), {
        'username': 'master',
        'password': 'masterpass',
        'node_address': '127.0.0.1:8000',
        'public_key': 'sample_public_key'
    }, format='json')
    logger.info(f"Response status code for master node registration: {response.status_code}")
    logger.info(f"Response data for master node registration: {response.json()}")

    assert response.status_code == 200
    assert response.json() == {'status': 'registered', 'node': '127.0.0.1:8000'}
    master_node = Node.objects.get(address='127.0.0.1:8000')
    logger.info(f"Master node registered with address: {master_node.address}")

    logger.info("Simulating registering a new node...")
    response = client.post(reverse('register_node'), {
        'username': 'new_node_user',
        'password': 'newpass',
        'node_address': '127.0.0.1:8001',
        'public_key': 'new_public_key'
    }, format='json')
    logger.info(f"Response status code for new node registration: {response.status_code}")
    logger.info(f"Response data for new node registration: {response.json()}")

    assert response.status_code == 200
    assert response.json() == {'status': 'registered', 'node': '127.0.0.1:8001'}
    new_node = Node.objects.get(address='127.0.0.1:8001')
    logger.info(f"New node registered with address: {new_node.address}")
class TestQuantumappConfig(TestCase):

    @patch('quantumapp.apps.threading.Thread')
    @patch('builtins.print')
    def test_ready(self, mock_print, mock_thread):
        # Create a dummy app module with a path attribute
        class DummyAppModule:
            __name__ = 'quantumapp'
            __path__ = ['/home/myuser/myquantumproject/quantumapp']

        # Patch get_app_config to return a QuantumappConfig with a valid path
        with patch('django.apps.apps.get_app_config', return_value=QuantumappConfig('quantumapp', DummyAppModule)):
            config = QuantumappConfig('quantumapp', DummyAppModule)

            # Capture the logs
            with self.assertLogs('quantumapp.apps', level='INFO') as cm:
                try:
                    config.ready()
                except Exception as e:
                    logger.error(f"Exception occurred: {e}", exc_info=True)
                    raise

            # Assert log messages
            self.assertIn("INFO:quantumapp.apps:Entering QuantumappConfig.ready() method...", cm.output)
            self.assertIn("INFO:quantumapp.apps:Exiting QuantumappConfig.ready() method...", cm.output)

        # Assert that print was called
        mock_print.assert_any_call("QuantumappConfig is ready")

        # Manually trigger startup tasks since the signal may not be working in test environment
        config.startup_tasks(None)

        # Assert that Thread was started
        self.assertTrue(mock_thread.called, "Thread creation was not called")

        # Ensure the created threads are correct
        thread_args = mock_thread.call_args_list
        self.assertEqual(len(thread_args), 2, "Expected two threads to be created")

        # Check that the threads were started
        for call in thread_args:
            thread_instance = call.return_value
            self.assertTrue(thread_instance.start.called, "Thread start was not called")

    @patch('quantumapp.apps.threading.Thread')
    def test_startup_tasks(self, mock_thread):
        # Create a dummy app module with a path attribute
        class DummyAppModule:
            __name__ = 'quantumapp'
            __path__ = ['/home/myuser/myquantumproject/quantumapp']

        config = QuantumappConfig('quantumapp', DummyAppModule)
        config.startup_tasks(None)

        # Ensure the created threads are correct
        thread_args = mock_thread.call_args_list
        self.assertEqual(len(thread_args), 2, "Expected two threads to be created")

        # Check that the threads were started
        for call in thread_args:
            thread_instance = call.return_value
            self.assertTrue(thread_instance.start.called, "Thread start was not called")

class NodeRegistrationTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.master_node_data = {
            'username': 'master',
            'password': 'masterpass',
            'node_address': '127.0.0.1:8000',
            'public_key': 'sample_public_key'
        }
        self.new_node_data = {
            'username': 'new_node_user',
            'password': 'newpass',
            'node_address': '127.0.0.1:8001',
            'public_key': 'new_public_key'
        }

    def test_register_master_node(self):
        logger.info("Testing master node registration...")
        response = self.client.post(reverse('register_node'), self.master_node_data, content_type="application/json")
        logger.info(f"Response status code for master node registration: {response.status_code}")
        logger.info(f"Response data for master node registration: {response.json()}")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Node.objects.filter(address=self.master_node_data['node_address']).exists())
        logger.info("Master node registered successfully.")

    def test_register_new_node(self):
        logger.info("Testing new node registration...")
        # First, register the master node
        self.client.post(reverse('register_node'), self.master_node_data, content_type="application/json")
        
        # Now, register a new node
        response = self.client.post(reverse('register_node'), self.new_node_data, content_type="application/json")
        logger.info(f"Response status code for master node registration: {response.status_code}")
        logger.info(f"Response data for master node registration: {response.json()}")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Node.objects.filter(address=self.master_node_data['node_address']).exists())
        logger.info("Master node registered successfully.")

    def test_register_new_node(self):
        logger.info("Testing new node registration...")
        # First, register the master node
        self.client.post(reverse('register_node'), self.master_node_data, content_type="application/json")
        
        # Now, register a new node
        response = self.client.post(reverse('register_node'), self.new_node_data, content_type="application/json")
        logger.info(f"Response status code for new node registration: {response.status_code}")
        logger.info(f"Response data for new node registration: {response.json()}")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Node.objects.filter(address=self.new_node_data['node_address']).exists())

        # Verify that the new node is registered correctly
        new_node = Node.objects.get(address=self.new_node_data['node_address'])
        self.assertEqual(new_node.public_key, self.new_node_data['public_key'])
        logger.info("New node registered successfully.")
