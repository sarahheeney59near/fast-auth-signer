import { createKey, isPassKeyAvailable } from '@near-js/biometric-ed25519/lib';
import { captureException } from '@sentry/react';
import BN from 'bn.js';
import { fetchSignInMethodsForEmail, sendSignInLinkToEmail } from 'firebase/auth';
import React, { useCallback, useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate, useSearchParams } from 'react-router-dom';
import styled from 'styled-components';

import { Button } from '../../lib/Button';
import FirestoreController from '../../lib/firestoreController';
import { openToast } from '../../lib/Toast';
import { useAuthState } from '../../lib/useAuthState';
import { decodeIfTruthy, inIframe, redirectWithError } from '../../utils';
import { basePath } from '../../utils/config';
import { checkFirestoreReady, firebaseAuth } from '../../utils/firebase';
import { isValidEmail } from '../../utils/form-validation';

const StyledContainer = styled.div`
  width: 100%;
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f2f1ea;
  padding: 0 16px;
  padding-bottom: 60px;
`;

const FormContainer = styled.form`
  max-width: 360px;
  width: 100%;
  margin: 16px auto;
  background-color: #ffffff;
  padding: 16px;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  gap: 16px;
`;

const InputContainer = styled.div`
  width: 100%;
  display: flex;
  flex-direction: column;
  margin-bottom: 10px;

  label {
    font-size: 12px;
    font-weight: 500;
  }

  input {
    padding: 8px 12px;
    border: 1px solid #e5e5e5;
    border-radius: 10px;
    font-size: 14px;
    margin-top: 4px;
    min-height: 50px;
    cursor: text;

    &:focus {
      outline: none;
      border: 1px solid #e5e5e5;
    }
  }

  .subText {
    font-size: 12px;
  }
`;

export const handleCreateAccount = async ({
  accountId, email, isRecovery, success_url, failure_url, public_key, contract_id, methodNames
}) => {
  const passkeyAvailable = await isPassKeyAvailable();
  let publicKeyWebAuthn; let keyPair;
  if (passkeyAvailable) {
    keyPair = await createKey(email);
    publicKeyWebAuthn = keyPair.getPublicKey().toString();
  }

  const searchParams = new URLSearchParams({
    ...(publicKeyWebAuthn ? { publicKeyFak: publicKeyWebAuthn } : {}),
    ...(accountId ? { accountId } : {}),
    ...(isRecovery ? { isRecovery } : {}),
    ...(success_url ? { success_url } : {}),
    ...(failure_url ? { failure_url } : {}),
    ...(public_key ? { public_key_lak: public_key } : {}),
    ...(contract_id ? { contract_id } : {}),
    ...(methodNames ? { methodNames } : {})
  });

  if (publicKeyWebAuthn) {
    window.localStorage.setItem(`temp_fastauthflow_${publicKeyWebAuthn}`, keyPair.toString());
  }

  await sendSignInLinkToEmail(firebaseAuth, email, {
    url: encodeURI(
      `${window.location.origin}${basePath ? `/${basePath}` : ''}/auth-callback?${searchParams.toString()}`,
    ),
    handleCodeInApp: true,
  });
  window.localStorage.setItem('emailForSignIn', email);
  return {
    email, publicKey: publicKeyWebAuthn, accountId, privateKey: keyPair && keyPair.toString()
  };
};

function SignInPage() {
  const { register, handleSubmit, setValue } = useForm();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const skipGetKey = decodeIfTruthy(searchParams.get('skipGetKey'));
  const { authenticated } = useAuthState(skipGetKey);
  const [renderRedirectButton, setRenderRedirectButton] = useState('');

  if (!window.firestoreController) {
    window.firestoreController = new FirestoreController();
  }

  const addDevice = useCallback(async (data: any) => {
    if (!data.email) return;

    const success_url = searchParams.get('success_url');
    const failure_url = searchParams.get('failure_url');
    const public_key =  searchParams.get('public_key');
    const contract_id = searchParams.get('contract_id');
    const methodNames = searchParams.get('methodNames');

    try {
      const result = await fetchSignInMethodsForEmail(firebaseAuth, data.email);
      if (!result.length) {
        throw new Error('Account not found, please create an account and try again');
      }
      const { publicKey: publicKeyFak, email, privateKey } = await handleCreateAccount({
        accountId:   null,
        email:       data.email,
        isRecovery:  true,
        success_url,
        failure_url,
        public_key,
        contract_id,
        methodNames,
      });
      const newSearchParams = new URLSearchParams({
        email,
        isRecovery: 'true',
        ...(publicKeyFak ? { publicKeyFak } : {}),
        ...(success_url ? { success_url } : {}),
        ...(failure_url ? { failure_url } : {}),
        ...(public_key ? { public_key_lak: public_key } : {}),
        ...(contract_id ? { contract_id } : {}),
        ...(methodNames ? { methodNames } : {})
      });
      const hashParams = new URLSearchParams({ ...(privateKey ? { privateKey } : {}) });
      navigate(`/verify-email?${newSearchParams.toString()}#${hashParams.toString()}`);
    } catch (error: any) {
      redirectWithError({ success_url, failure_url, error });

      if (typeof error?.message === 'string') {
        openToast({
          type:  'ERROR',
          title: error.message,
        });
      } else {
        openToast({
          type:  'ERROR',
          title: 'Something went wrong',
        });
      }
    }
  }, [searchParams, navigate]);

  useEffect(() => {
    if (authenticated === 'loading') return;

    const handleAuthCallback = async () => {
      const isFirestoreReady = await checkFirestoreReady();

      const success_url = decodeIfTruthy(searchParams.get('success_url'));
      const failure_url = decodeIfTruthy(searchParams.get('failure_url'));
      const public_key =  decodeIfTruthy(searchParams.get('public_key'));
      const contract_id = decodeIfTruthy(searchParams.get('contract_id'));
      const methodNames = decodeIfTruthy(searchParams.get('methodNames'));
      const email = decodeIfTruthy(searchParams.get('email'));

      const parsedUrl = new URL(success_url || window.location.origin + (basePath ? `/${basePath}` : ''));

      if (authenticated === true && isFirestoreReady) {
        if (!public_key || !contract_id) {
          window.location.replace(parsedUrl.href);
          return;
        }
        const publicKeyFak = await window.fastAuthController.getPublicKey();
        const existingDevice = await window.firestoreController.getDeviceCollection(publicKeyFak);
        const existingDeviceLakKey = existingDevice?.publicKeys?.filter((key) => key !== publicKeyFak)[0];
        // if given lak key is already attached to webAuthN public key, no need to add it again
        const noNeedToAddKey = existingDeviceLakKey === public_key;

        parsedUrl.searchParams.set('account_id', window.fastAuthController.getAccountId());
        parsedUrl.searchParams.set('public_key', public_key);
        parsedUrl.searchParams.set('all_keys', [public_key, publicKeyFak].join(','));

        if (noNeedToAddKey) {
          if (inIframe()) {
            setRenderRedirectButton(parsedUrl.href);
          } else {
            window.location.replace(parsedUrl.href);
          }
          return;
        }

        try {
          const res = await window.fastAuthController.signAndSendAddKey({
            contractId: contract_id,
            methodNames,
            allowance:  new BN('250000000000000'),
            publicKey:  public_key,
          });
          const resJSON = res && res.json();

          const failure = resJSON['Receipts Outcome'].find(({ outcome: { status } }) => Object.keys(status).some((k) => k === 'Failure'))?.outcome.status.Failure;

          if (failure?.ActionError?.kind?.LackBalanceForState) {
            navigate(`/devices?${searchParams.toString()}`);
            return;
          }

          // Add device
          const user = firebaseAuth.currentUser;
          window.firestoreController.updateUser({
            userUid:   user.uid,
            // User type is missing accessToken but it exist
            // @ts-ignore
            oidcToken: user.accessToken,
          });

          // Since FAK is already added, we only add LAK
          await window.firestoreController.addDeviceCollection({
            fakPublicKey:  null,
            lakPublicKey: public_key,
            gateway:      success_url,
          });

          window.parent.postMessage({
            type:   'method',
            method: 'query',
            id:     1234,
            params: {
              request_type: 'complete_sign_in',
              publicKey:    public_key,
              allKeys:      [public_key, publicKeyFak].join(','),
              accountId:    (window as any).fastAuthController.getAccountId()
            }
          }, '*');
          if (inIframe()) {
            setRenderRedirectButton(parsedUrl.href);
          } else {
            window.location.replace(parsedUrl.href);
          }
        } catch (error) {
          captureException(error);
          redirectWithError({ success_url, failure_url, error });
          openToast({
            type:  'ERROR',
            title: error.message,
          });
        }
      } else if (email && !authenticated) {
        // once it has email but not authenicated, it means existing passkey is not valid anymore, therefore remove webauthn_username and try to create a new passkey
        window.localStorage.removeItem('webauthn_username');
        setValue('email', email);
        addDevice({ email });
      }
    };

    handleAuthCallback();
  }, [authenticated]);

  if (authenticated === true) {
    return renderRedirectButton ? (
      <Button
        label="Back to app"
        onClick={() => {
          window.open(renderRedirectButton, '_parent');
        }}
      />
    ) : (
      <div>Signing transaction</div>
    );
  }

  if (authenticated instanceof Error) {
    return <div>{authenticated.message}</div>;
  }

  if (inIframe()) {
    return (
      <Button
        label="Continue on fast auth"
        onClick={() => {
          const url = !authenticated ? `${window.location.href}&skipGetKey=true` : window.location.href;
          window.open(url, '_parent');
        }}
      />
    );
  }

  const onSubmit = handleSubmit(addDevice);

  return (
    <StyledContainer>
      <FormContainer onSubmit={onSubmit}>
        <header>
          <h1>Sign In</h1>
          <p className="desc">Use this account to sign in everywhere on NEAR, no password required.</p>
        </header>

        <InputContainer>
          <label htmlFor="email">
            Email
            <input
              {...register('email', {
                required: 'Please enter a valid email address',
              })}
              onChange={(e) => {
                setValue('email', e.target.value);
                // eslint-disable-next-line
              if (!isValidEmail(e.target.value)) return;
              }}
              placeholder="user_name@email.com"
              type="email"
              id="email"
              data-test-id="add-device-email"
              required
            />
          </label>

        </InputContainer>

        <Button type="submit" size="large" label="Continue" variant="affirmative" data-test-id="add-device-continue-button" onClick={onSubmit} />
      </FormContainer>
    </StyledContainer>
  );
}

export default SignInPage;
