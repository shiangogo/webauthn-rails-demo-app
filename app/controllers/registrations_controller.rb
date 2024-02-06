# frozen_string_literal: true

class RegistrationsController < ApplicationController
  def new
  end

  def create
    user = User.new(username: params[:registration][:username])

    create_options = relying_party.options_for_registration(
      user: {
        name: params[:registration][:username],
        id: user.webauthn_id
      },
      authenticator_selection: { user_verification: "required" }
    )

    if user.valid?
      session[:current_registration] = { challenge: create_options.challenge, user_attributes: user.attributes }
      p "***************************************************"
      p "session: "
      p session[:current_registration]
      p "user.attributes: "
      p user.attributes
      p "challenge: "
      p create_options.challenge
      p "***************************************************"

      respond_to do |format|
        format.json { render json: create_options }
      end
    else
      respond_to do |format|
        format.json { render json: { errors: user.errors.full_messages }, status: :unprocessable_entity }
      end
    end
  end

  def callback
    p "***************************************************"
    p session[:current_registration]
    p session[:current_registration][:user_attributes]
    p "***************************************************"
    user = User.create!(session[:current_registration][:user_attributes])
    # if User.create! fails, it will raise an ActiveRecord::RecordInvalid error.

    begin
      webauthn_credential = relying_party.verify_registration(
        params, # raw_credential
        session[:current_registration][:challenge], # challenge
        user_verification: true, # user_verification
      )

      # User has_many credentials
      credential = user.credentials.build(
        external_id: Base64.strict_encode64(webauthn_credential.raw_id),
        nickname: params[:credential_nickname],
        public_key: webauthn_credential.public_key,
        sign_count: webauthn_credential.sign_count
      )

      if credential.save
        sign_in(user)

        render json: { status: "ok" }, status: :ok
      else
        render json: "Couldn't register your Security Key", status: :unprocessable_entity
      end
    rescue WebAuthn::Error => e
      render json: "Verification failed: #{e.message}", status: :unprocessable_entity
    ensure
      session.delete(:current_registration)
    end
  end
end
