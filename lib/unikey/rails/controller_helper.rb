# frozen_string_literal: true

module UniKey
  module Rails
    # Controller helper for verifying UniKey signatures in Rails
    #
    # @example
    #   class Api::AgentController < ApplicationController
    #     include UniKey::Rails::ControllerHelper
    #     before_action :verify_unikey_signature
    #
    #     def balance
    #       # @verified_request.agent_email is the authenticated agent
    #       render json: { balance: current_campaign.total }
    #     end
    #   end
    #
    module ControllerHelper
      extend ActiveSupport::Concern

      included do
        # Make verified_request available to views if needed
        helper_method :verified_request if respond_to?(:helper_method)
      end

      # Verify the UniKey signature on the current request
      #
      # Sets @verified_request with the verified request info on success.
      # Renders 401 Unauthorized on failure.
      def verify_unikey_signature
        @verified_request = UniKey.verify!(request)
      rescue UniKey::InvalidSignature
        render_unikey_error("Invalid signature", :unauthorized)
      rescue UniKey::ExpiredRequest
        render_unikey_error("Request has expired", :unauthorized)
      rescue UniKey::MissingHeaders => e
        render_unikey_error(e.message, :bad_request)
      rescue UniKey::DNSLookupFailed => e
        render_unikey_error("Unknown signer: #{e.domain}", :unauthorized)
      rescue UniKey::UntrustedSigner => e
        render_unikey_error("Untrusted signer: #{e.signer}", :unauthorized)
      end

      # Optional: verify but don't require (sets @verified_request or nil)
      def verify_unikey_signature_optional
        @verified_request = UniKey.verify(request)
      end

      # Get the verified request info (available after verify_unikey_signature)
      def verified_request
        @verified_request
      end

      # Get the authenticated agent's email (available after verify_unikey_signature)
      def agent_email
        @verified_request&.agent_email
      end

      private

      def render_unikey_error(message, status)
        render json: { error: "unauthorized", reason: message }, status: status
      end
    end
  end
end
