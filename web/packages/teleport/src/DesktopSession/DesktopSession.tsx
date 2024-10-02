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

import React, { useState, useEffect } from 'react';
import { Indicator, Box, Flex, ButtonSecondary, ButtonPrimary } from 'design';
import { Info } from 'design/Alert';
import Dialog, {
  DialogHeader,
  DialogTitle,
  DialogContent,
  DialogFooter,
} from 'design/Dialog';
import { Attempt } from 'shared/hooks/useAttemptNext';

import TdpClientCanvas from 'teleport/components/TdpClientCanvas';
import AuthnDialog from 'teleport/components/AuthnDialog';

import useDesktopSession, {
  clipboardSharingMessage,
  directorySharingPossible,
  getDisplaySize,
  isSharingClipboard,
  isSharingDirectory,
} from './useDesktopSession';
import TopBar from './TopBar';

import type { State, TdpConnection } from './useDesktopSession';
import type { WebAuthnState } from 'teleport/lib/useWebAuthn';

export function DesktopSessionContainer() {
  const state = useDesktopSession();
  return <DesktopSession {...state} />;
}

declare global {
  interface Window {
    showDirectoryPicker: () => Promise<FileSystemDirectoryHandle>;
  }
}

export function DesktopSession(props: State) {
  const {
    webauthn,
    tdpClient,
    username,
    hostname,
    tdpConnection,
    onMouseDown,
    onFocusOut,
    onMouseWheelScroll,
    onKeyDown,
    onKeyUp,
    onMouseUp,
    onMouseMove,
    onCtrlAltDel,
    alerts,
    onRemoveAlert,
    onShareDirectory,
    onDisconnect,
    clipboardSharingState,
    directorySharingState,
    clientCanvasProps,
    windowOnResize,
    fetchAttempt,
    showAnotherSessionActiveDialog,
  } = props;

  const [screenState, setScreenState] = useState<ScreenState>({
    screen: 'processing',
    canvasState: { shouldConnect: false, shouldDisplay: false },
  });

  // Calculate the next `ScreenState` whenever any of the constituent pieces of state change.
  useEffect(() => {
    setScreenState(prevState =>
      nextScreenState(
        prevState,
        fetchAttempt,
        tdpConnection,
        showAnotherSessionActiveDialog,
        webauthn
      )
    );
  }, [fetchAttempt, tdpConnection, showAnotherSessionActiveDialog, webauthn]);

  // Call connect after all listeners have been registered
  useEffect(() => {
    if (tdpClient && screenState.canvasState.shouldConnect) {
      const client = tdpClient.current;
      client.connect(getDisplaySize());
      return () => {
        client.shutdown();
      };
    }
  }, [screenState.canvasState.shouldConnect, tdpClient]);

  return (
    <Flex flexDirection="column">
      <TopBar
        onDisconnect={onDisconnect}
        userHost={`${username}@${hostname}`}
        onShareDirectory={onShareDirectory}
        canShareDirectory={directorySharingPossible(directorySharingState)} // could probably export this value from useDesktopSession
        isSharingDirectory={isSharingDirectory(directorySharingState)}
        isSharingClipboard={isSharingClipboard(clipboardSharingState)}
        clipboardSharingMessage={clipboardSharingMessage(clipboardSharingState)}
        onCtrlAltDel={onCtrlAltDel}
        alerts={alerts}
        onRemoveAlert={onRemoveAlert}
      />

      {screenState.screen === 'anotherSessionActive' && (
        <AnotherSessionActiveDialog {...props} />
      )}
      {screenState.screen === 'mfa' && <MfaDialog webauthn={webauthn} />}
      {screenState.screen === 'alert dialog' && (
        <AlertDialog screenState={screenState} />
      )}
      {screenState.screen === 'processing' && <Processing />}

      <TdpClientCanvas
        {...clientCanvasProps}
        onMouseWheelScroll={onMouseWheelScroll}
        onMouseUp={onMouseUp}
        onMouseMove={onMouseMove}
        onFocusOut={onFocusOut}
        windowOnResize={windowOnResize}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
        onMouseDownDS={onMouseDown}
        style={{
          display: 'flex',
        }}
      />
    </Flex>
  );
}

const MfaDialog = ({ webauthn }: { webauthn: WebAuthnState }) => {
  return (
    <AuthnDialog
      onContinue={webauthn.authenticate}
      onCancel={() => {
        webauthn.setState(prevState => {
          return {
            ...prevState,
            errorText:
              'This session requires multi factor authentication to continue. Please hit "Retry" and follow the prompts given by your browser to complete authentication.',
          };
        });
      }}
      errorText={webauthn.errorText}
    />
  );
};

const AlertDialog = ({ screenState }: { screenState: ScreenState }) => (
  <Dialog dialogCss={() => ({ width: '484px' })} open={true}>
    <DialogHeader style={{ flexDirection: 'column' }}>
      <DialogTitle>Disconnected</DialogTitle>
    </DialogHeader>
    <DialogContent>
      <>
        <Info
          children={<>{screenState.alertMessage || invalidStateMessage}</>}
        />
        Refresh the page to reconnect.
      </>
    </DialogContent>
    <DialogFooter>
      <ButtonSecondary
        size="large"
        width="30%"
        onClick={() => {
          window.location.reload();
        }}
      >
        Refresh
      </ButtonSecondary>
    </DialogFooter>
  </Dialog>
);

// TODO (avatus) : dont pass the entire state here if we only need 1 method
const AnotherSessionActiveDialog = (props: State) => {
  return (
    <Dialog
      dialogCss={() => ({ width: '484px' })}
      onClose={() => {}}
      open={true}
    >
      <DialogHeader style={{ flexDirection: 'column' }}>
        <DialogTitle>Another Session Is Active</DialogTitle>
      </DialogHeader>
      <DialogContent>
        This desktop has an active session, connecting to it may close the other
        session. Do you wish to continue?
      </DialogContent>
      <DialogFooter>
        <ButtonPrimary
          mr={3}
          onClick={() => {
            window.close();
          }}
        >
          Abort
        </ButtonPrimary>
        <ButtonSecondary
          onClick={() => {
            props.setShowAnotherSessionActiveDialog(false);
          }}
        >
          Continue
        </ButtonSecondary>
      </DialogFooter>
    </Dialog>
  );
};

const Processing = () => {
  return (
    <Box textAlign="center" m={10}>
      <Indicator />
    </Box>
  );
};

const invalidStateMessage = 'internal application error';

/**
 * Calculate the next `ScreenState` based on the current state and the latest
 * attempts to fetch the desktop session, connect to the TDP server, and connect
 * to the websocket.
 */
const nextScreenState = (
  prevState: ScreenState,
  fetchAttempt: Attempt,
  tdpConnection: TdpConnection,
  showAnotherSessionActiveDialog: boolean,
  webauthn: WebAuthnState
): ScreenState => {
  // We always want to show the user the first alert that caused the session to fail/end,
  // so if we're already showing an alert, don't change the screen.
  //
  // This allows us to track the various pieces of the state independently and always display
  // the vital information to the user. For example, we can track the TDP connection status
  // and the websocket connection status separately throughout the codebase. If the TDP connection
  // fails, and then the websocket closes, we want to show the `tdpConnection.statusText` to the user,
  // not the `wsConnection.statusText`. But if the websocket closes unexpectedly before a TDP message telling
  // us why, we want to show the websocket closing message to the user.
  if (prevState.screen === 'alert dialog') {
    return prevState;
  }

  // Otherwise, calculate a new screen state.
  const showAnotherSessionActive = showAnotherSessionActiveDialog;
  const showMfa = webauthn.requested;
  const showAlert =
    fetchAttempt.status === 'failed' || // TODO(zmb3) handle websocket closed // Fetch attempt failed
    tdpConnection.status === 'closed'; // TDP connection failed

  const atLeastOneAttemptProcessing =
    fetchAttempt.status === 'processing' || tdpConnection.status === '';
  const noDialogs = !(showMfa || showAnotherSessionActive || showAlert);
  const showProcessing = atLeastOneAttemptProcessing && noDialogs;

  if (showAnotherSessionActive) {
    // Highest priority: we don't want to connect (`shouldConnect`) until
    // the user has decided whether to continue with the active session.
    return {
      screen: 'anotherSessionActive',
      canvasState: { shouldConnect: false, shouldDisplay: false },
    };
  } else if (showMfa) {
    // Second highest priority. Secondary to `showAnotherSessionActive` because
    // this won't happen until the user has decided whether to continue with the active session.
    //
    // `shouldConnect` is true because we want to maintain the websocket connection that the mfa
    // request was made over.
    return {
      screen: 'mfa',
      canvasState: { shouldConnect: true, shouldDisplay: false },
    };
  } else if (showAlert) {
    // Third highest priority. If either attempt or the websocket has failed, show the alert.
    return {
      screen: 'alert dialog',
      alertMessage: calculateAlertMessage(
        fetchAttempt,
        tdpConnection,
        showAnotherSessionActiveDialog,
        prevState
      ),
      canvasState: { shouldConnect: false, shouldDisplay: false },
    };
  } else if (showProcessing) {
    // Fourth highest priority. If at least one attempt is still processing, show the processing indicator
    // while trying to connect to the TDP server via the websocket.
    const shouldConnect = fetchAttempt.status !== 'processing';
    return {
      screen: 'processing',
      canvasState: { shouldConnect, shouldDisplay: false },
    };
  } else {
    // Default state: everything is good, so show the canvas.
    return {
      screen: 'canvas',
      canvasState: { shouldConnect: true, shouldDisplay: true },
    };
  }
};

/**
 * Calculate the error message to display to the user based on the current state.
 */
/* eslint-disable no-console */
const calculateAlertMessage = (
  fetchAttempt: Attempt,
  tdpConnection: TdpConnection,
  showAnotherSessionActiveDialog: boolean,
  prevState: ScreenState
): string => {
  let message = '';
  if (fetchAttempt.status === 'failed') {
    message = fetchAttempt.statusText || 'fetch attempt failed';
  } else if (tdpConnection.status === 'open') {
    message = tdpConnection.statusText || 'TDP connection failed';
  } else if (tdpConnection.status === 'closed') {
    message = tdpConnection.statusText || 'TDP connection ended gracefully';
  } else {
    console.error('invalid state');
    console.error({
      fetchAttempt,
      tdpConnection,
      showAnotherSessionActiveDialog,
      prevState,
    });
    message = invalidStateMessage;
  }
  return message;
};
/* eslint-enable no-console */

type ScreenState = {
  screen:
    | 'mfa' // tell the user they are about to be prompted for per-session MFA
    | 'anotherSessionActive' // show a dialog explaining that this desktop may have an active session
    | 'alert dialog' // show the "Disconnected" dialog
    | 'processing' // show a loading spinner
    | 'canvas'; // show the remote desktop session during normal operation

  alertMessage?: string;
  canvasState: {
    shouldConnect: boolean;
    shouldDisplay: boolean;
  };
};
