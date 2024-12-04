/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { useState } from 'react';
import useAttempt, { Attempt } from 'shared/hooks/useAttemptNext';

import auth from 'teleport/services/auth';
import { MfaChallengeScope } from 'teleport/services/auth/auth';

import {
  getMfaChallengeOptions as getChallengeOptions,
  DeviceType,
  MfaAuthenticateChallenge,
  MfaChallengeResponse,
  MfaOption,
} from 'teleport/services/mfa';

export default function useReAuthenticate(props: ReauthProps): ReauthState {
  // Note that attempt state "success" is not used or required.
  // After the user submits, the control is passed back
  // to the caller who is responsible for rendering the `ReAuthenticate`
  // component.
  const { attempt, setAttempt } = useAttempt('');

  // Provide a custom error handler to catch a webauthn frontend error that occurs
  // on Firefox and replace it with a more helpful error message.
  const handleError = (err: Error) => {
    if (err.message.includes('attempt was made to use an object that is not')) {
      setAttempt({
        status: 'failed',
        statusText:
          'The two-factor device you used is not registered on this account. You must verify using a device that has already been registered.',
      });
      return;
    } else {
      setAttempt({ status: 'failed', statusText: err.message });
      return;
    }
  };

  const [mfaChallenge, setMfaChallenge] =
    useState<MfaAuthenticateChallenge>(null);

  async function getMfaChallenge() {
    if (mfaChallenge) {
      return mfaChallenge;
    }

    return auth.getMfaChallenge({ scope: props.challengeScope }).then(chal => {
      setMfaChallenge(chal);
      return chal;
    });
  }

  function clearMfaChallenge() {
    setMfaChallenge(null);
  }

  function getMfaChallengeOptions() {
    return getMfaChallenge().then(getChallengeOptions);
  }

  function submitWithMfa(mfaType?: DeviceType, totp_code?: string) {
    setAttempt({ status: 'processing' });
    return getMfaChallenge()
      .then(chal => auth.getMfaChallengeResponse(chal, mfaType, totp_code))
      .then(props.onMfaResponse)
      .finally(clearMfaChallenge)
      .catch(handleError);
  }

  function submitWithPasswordless() {
    setAttempt({ status: 'processing' });
    // Always get a new passwordless challenge, the challenge stored in state is for mfa
    // and will also be overwritten in the backend by the passwordless challenge.
    return auth
      .getMfaChallenge({
        scope: props.challengeScope,
        userVerificationRequirement: 'required',
      })
      .then(chal => auth.getMfaChallengeResponse(chal, 'webauthn'))
      .then(props.onMfaResponse)
      .finally(clearMfaChallenge)
      .catch(handleError);
  }

  function clearAttempt() {
    setAttempt({ status: '' });
  }

  return {
    attempt,
    clearAttempt,
    mfaChallenge,
    setMfaChallenge,
    getMfaChallenge,
    getMfaChallengeOptions,
    submitWithMfa,
    submitWithPasswordless,
  };
}

export type ReauthProps = {
  challengeScope: MfaChallengeScope;
  onMfaResponse(res: MfaChallengeResponse): void;
};

export type ReauthState = {
  attempt: Attempt;
  clearAttempt: () => void;
  mfaChallenge: MfaAuthenticateChallenge;
  setMfaChallenge: (challenge: MfaAuthenticateChallenge) => void;
  getMfaChallenge: () => Promise<MfaAuthenticateChallenge>;
  getMfaChallengeOptions: () => Promise<MfaOption[]>;
  submitWithMfa: (mfaType?: DeviceType, totp_code?: string) => Promise<void>;
  submitWithPasswordless: () => Promise<void>;
};
