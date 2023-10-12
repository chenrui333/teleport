# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from teleport.samlidp.v1 import samlidp_pb2 as teleport_dot_samlidp_dot_v1_dot_samlidp__pb2


class SAMLIdPServiceStub(object):
    """SAMLIdPService provides utility methods for the SAML identity provider.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.ProcessSAMLIdPRequest = channel.unary_unary(
                '/teleport.samlidp.v1.SAMLIdPService/ProcessSAMLIdPRequest',
                request_serializer=teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestRequest.SerializeToString,
                response_deserializer=teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestResponse.FromString,
                )


class SAMLIdPServiceServicer(object):
    """SAMLIdPService provides utility methods for the SAML identity provider.
    """

    def ProcessSAMLIdPRequest(self, request, context):
        """ProcessSAMLIdPRequest processes the SAML auth request.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_SAMLIdPServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'ProcessSAMLIdPRequest': grpc.unary_unary_rpc_method_handler(
                    servicer.ProcessSAMLIdPRequest,
                    request_deserializer=teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestRequest.FromString,
                    response_serializer=teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'teleport.samlidp.v1.SAMLIdPService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class SAMLIdPService(object):
    """SAMLIdPService provides utility methods for the SAML identity provider.
    """

    @staticmethod
    def ProcessSAMLIdPRequest(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/teleport.samlidp.v1.SAMLIdPService/ProcessSAMLIdPRequest',
            teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestRequest.SerializeToString,
            teleport_dot_samlidp_dot_v1_dot_samlidp__pb2.ProcessSAMLIdPRequestResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
