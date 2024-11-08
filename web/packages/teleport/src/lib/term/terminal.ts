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

import '@xterm/xterm/css/xterm.css';
import { ITheme, Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon, ISearchOptions } from '@xterm/addon-search';
import { WebglAddon } from '@xterm/addon-webgl';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { CanvasAddon } from '@xterm/addon-canvas';
import { debounce, isInteger } from 'shared/utils/highbar';
import Logger from 'shared/libs/logger';

import cfg from 'teleport/config';

import { TermEvent } from './enums';
import Tty from './tty';

import type { DebouncedFunc } from 'shared/utils/highbar';

const logger = Logger.create('lib/term/terminal');
const DISCONNECT_TXT = 'disconnected';
const WINDOW_RESIZE_DEBOUNCE_DELAY = 200;

/**
 * TtyTerminal is a wrapper on top of xtermjs
 */
export default class TtyTerminal {
  term: Terminal;
  tty: Tty;

  _el: HTMLElement;
  _scrollBack: number;
  _fontFamily: string;
  _fontSize: number;
  _convertEol: boolean;
  _debouncedResize: DebouncedFunc<() => void>;
  _fitAddon = new FitAddon();
  _searchAddon = new SearchAddon();
  _webLinksAddon = new WebLinksAddon();
  _webglAddon: WebglAddon;
  _canvasAddon = new CanvasAddon();

  constructor(
    tty: Tty,
    private options: Options
  ) {
    const { el, scrollBack, fontFamily, fontSize, convertEol } = options;
    this._el = el;
    this._fontFamily = fontFamily || undefined;
    this._fontSize = fontSize || 14;
    // Passing scrollback will overwrite the default config. This is to support ttyplayer.
    // Default to the config when not passed anything, which is the normal usecase
    this._scrollBack = scrollBack || cfg.ui.scrollbackLines;
    this._convertEol = convertEol || false;
    this.tty = tty;
    this.term = null;

    this._debouncedResize = debounce(() => {
      this._requestResize();
    }, WINDOW_RESIZE_DEBOUNCE_DELAY);
  }

  open() {
    this.term = new Terminal({
      lineHeight: 1,
      fontFamily: this._fontFamily,
      fontSize: this._fontSize,
      scrollback: this._scrollBack,
      convertEol: this._convertEol,
      cursorBlink: false,
      minimumContrastRatio: 4.5, // minimum for WCAG AA compliance
      theme: this.options.theme,
      allowProposedApi: true, // required for customizing SearchAddon properties
    });

    this.term.loadAddon(this._fitAddon);
    this.term.loadAddon(this._webLinksAddon);
    // handle context loss and load webgl addon
    try {
      // try to create a new WebglAddon. If webgl is not supported, this
      // constructor will throw an error and fallback to canvas. We also fallback
      // to canvas if the webgl context is lost after a timeout.
      // The "wait for context" timeout for the webgl addon doesn't actually start until the app is
      // able to have it back. For example, if the OS takes the gpu away from the browser, the timeout
      // wont start looking for the context again until the OS has given the browser the context again.
      // When the initial context lost event is fired, the webgl addon consumes the event
      // and waits for a bit to see if it can get the context back. If it fails repeatedly, it
      // will propagate the context loss event itself in which case we fall back to canvas
      this._webglAddon = new WebglAddon();
      this._webglAddon.onContextLoss(() => {
        this.fallbackToCanvas();
      });
      this.term.loadAddon(this._webglAddon);
    } catch (err) {
      this.fallbackToCanvas();
    }

    this.term.open(this._el);
    this._fitAddon.fit();
    this.term.focus();
    this.term.onData(data => {
      this.tty.send(data);
    });

    this.tty.on(TermEvent.RESET, () => this.reset());
    this.tty.on(TermEvent.CONN_CLOSE, e => this._processClose(e));
    this.tty.on(TermEvent.DATA, data => this._processData(data));

    // subscribe tty resize event (used by session player)
    this.tty.on(TermEvent.RESIZE, ({ h, w }) => this.resize(w, h));

    this.connect();

    // subscribe to window resize events
    window.addEventListener('resize', this._debouncedResize);
  }

  fallbackToCanvas() {
    logger.info('WebGL context lost. Falling back to canvas');
    this._webglAddon?.dispose();
    this._webglAddon = undefined;
    try {
      this.term.loadAddon(this._canvasAddon);
    } catch (err) {
      logger.error(
        'Canvas renderer could not be loaded. Falling back to default'
      );
      this._canvasAddon?.dispose();
      this._canvasAddon = undefined;
    }
  }

  connect() {
    this.tty.connect(this.term.cols, this.term.rows);
  }

  updateTheme(theme: ITheme): void {
    this.term.options.theme = theme;
  }

  destroy() {
    this._disconnect();
    this._debouncedResize.cancel();
    this._fitAddon.dispose();
    this._searchAddon?.dispose();
    this._webglAddon?.dispose();
    this._canvasAddon?.dispose();
    this._el.innerHTML = null;
    this.term?.dispose();

    window.removeEventListener('resize', this._debouncedResize);
  }

  loadSearchAddon({
    onDidChangeResults,
  }: {
    onDidChangeResults: (resultIndex: number, resultCount: number) => void;
  }) {
    this._searchAddon.onDidChangeResults(ev =>
      onDidChangeResults(ev.resultIndex, ev.resultCount)
    );
    this.term.loadAddon(this._searchAddon);
  }

  clearSearch() {
    this._searchAddon.clearDecorations();
  }

  search(
    searchString: string,
    searchPrevious: boolean,
    searchOpts?: ISearchOptions
  ) {
    if (!this._searchAddon) {
      throw new Error(
        '_searchAddon has not been loaded. Use `loadSearchAddon` before searching.'
      );
    }

    const opts: ISearchOptions = {
      // TODO (avatus): we are setting these defaults (regex/caseSensitive) to
      // what we think would be best UX, but the search UI could be expanded upon
      // to allow these values to be updated.
      regex: true,
      caseSensitive: false,
      ...searchOpts,
    };

    if (searchPrevious) {
      this._searchAddon.findPrevious(searchString, opts);
    } else {
      this._searchAddon.findNext(searchString, opts);
    }
  }

  reset() {
    this.term.reset();
  }

  resize(cols, rows) {
    try {
      // if not defined, use the size of the container
      if (!isInteger(cols) || !isInteger(rows)) {
        cols = this.term.cols;
        rows = this.term.rows;
      }

      if (cols === this.term.cols && rows === this.term.rows) {
        return;
      }

      this.term.resize(cols, rows);
    } catch (err) {
      logger.error('xterm.resize', { w: cols, h: rows }, err);
      this.term.reset();
    }
  }

  _disconnect() {
    this.tty.disconnect();
    this.tty.removeAllListeners();
  }

  _requestResize() {
    const visible = !!this._el.clientWidth && !!this._el.clientHeight;
    if (!visible) {
      logger.info(`unable to resize terminal (container might be hidden)`);
      return;
    }

    this._fitAddon.fit();
    this.tty.requestResize(this.term.cols, this.term.rows);
  }

  _processData(data) {
    try {
      this.tty.pauseFlow();

      // during a live session, data is emitted as a string.
      // during playback, data from the websocket comes over as a DataView
      const d: any = typeof data === 'string' ? data : new Uint8Array(data);
      this.term.write(d, () => this.tty.resumeFlow());
    } catch (err) {
      logger.error('xterm.write', data, err);
      // recover xtermjs by resetting it
      this.term.reset();
      this.tty.resumeFlow();
    }
  }

  _processClose(e) {
    const { reason } = e;
    let displayText = DISCONNECT_TXT;
    if (reason) {
      displayText = `${displayText}: ${reason}`;
    }

    displayText = `\x1b[31m${displayText}\x1b[m\r\n`;
    this.term.write(displayText);
  }
}

type Options = {
  el: HTMLElement;
  theme: ITheme;
  scrollBack?: number;
  fontFamily?: string;
  fontSize?: number;
  convertEol?: boolean;
};
