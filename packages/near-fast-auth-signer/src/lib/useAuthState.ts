/* eslint-disable import/prefer-default-export */
import { getKeys, isPassKeyAvailable } from '@near-js/biometric-ed25519/lib';
import { KeyPairEd25519 } from '@near-js/crypto';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom/dist';

import FastAuthController from './controller';
import { network, networkId } from '../utils/config';
import { checkFirestoreReady, firebaseAuth } from '../utils/firebase';

type AuthState = {
  authenticated: 'loading' | boolean | Error
}

export const useAuthState = (skipGetKeys = false): AuthState => {
  const [authenticated, setAuthenticated] = useState<AuthState['authenticated']>('loading');
  const webauthnUsername = useMemo(() => {
    try {
      return window.localStorage.getItem('webauthn_username');
    } catch (error) {
      return null;
    }
  }, []);

  const [controllerState, setControllerState] = useState<'loading' | boolean>('loading');
  const [isPassKeySupported, setIsPassKeySupported] = useState<boolean>(null);

  useEffect(() => {
    isPassKeyAvailable().then((isAvailable) => setIsPassKeySupported(isAvailable));
  }, []);

  const [query] = useSearchParams();

  useEffect(() => {
    if (isPassKeySupported === null) return;
    if (skipGetKeys) {
      setAuthenticated(false);
      setControllerState(false);
    } else if (controllerState !== false) {
      if (controllerState === true) {
        setAuthenticated(true);
      }
    } else if (!webauthnUsername && isPassKeySupported) {
      setAuthenticated(false);
    } else if (query.get('email') && query.get('email') !== webauthnUsername) {
      setAuthenticated(false);
    } else if (isPassKeySupported) {
      getKeys(webauthnUsername)
        .then((keypairs) => Promise.allSettled(
          keypairs.map((k) => fetch(`${network.fastAuth.authHelperUrl}/publicKey/${k.getPublicKey().toString()}/accounts`)
            .then((res) => res.json())
            .then((accIds) => accIds.map((accId) => { return { accId, keyPair: k }; })))
        ))
        .then(async (accounts) => {
          const accountsList = accounts.reduce((acc, curr) => (
            // eslint-disable-next-line no-undef
            curr && (curr as PromiseFulfilledResult<any>).value
              // eslint-disable-next-line no-undef
              ? acc.concat(...(curr as PromiseFulfilledResult<any>).value)
              : acc
          ), []);
          if (accountsList.length === 0) {
            setAuthenticated(false);
          } else {
            (window as any).fastAuthController = new FastAuthController({
              accountId: accountsList[0].accId,
              networkId
            });

            await window.fastAuthController.setKey(new KeyPairEd25519(accountsList[0].keyPair.toString().split(':')[1]));
            setAuthenticated(true);
          }
        }).catch(() => setAuthenticated(false));
    } else {
      checkFirestoreReady().then((isReady) => {
        if (isReady) {
          // @ts-ignore
          const oidcToken = firebaseAuth.currentUser.accessToken;
          if (window.fastAuthController.getLocalStoreKey(`oidc_keypair_${oidcToken}`)) {
            setAuthenticated(true);
          } else {
            setControllerState(false);
          }
        }
      });
    }
  }, [webauthnUsername, controllerState, query, isPassKeySupported]);

  useEffect(() => {
    if (window.fastAuthController) {
      window.fastAuthController.isSignedIn().then((isReady) => {
        setControllerState(isReady);
      });
    } else {
      setControllerState(false);
    }
  }, [controllerState, authenticated]);

  try {
    window.localStorage.getItem('webauthn_username');
    return { authenticated };
  } catch (error) {
    return { authenticated: new Error('Please allow third party cookies') };
  }
};
