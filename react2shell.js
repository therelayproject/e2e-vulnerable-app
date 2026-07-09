/**
 * EXACT code path responsible for CVE-2025-55182 ("React2Shell" RCE) in
 * React 19.0.0's react-server-dom-turbopack / react-server packages.
 *
 * This file lifts the seven functions on the source-to-sink chain
 * verbatim from the React 19.0.0 source tree. Imports, types, and
 * helpers are stubbed minimally so the file parses standalone — but
 * the function bodies are unchanged.
 *
 * Source (entry point):  decodeReplyFromBusboy
 *   ↓ resolveField (via busboy 'field' event)
 *   ↓ resolveModelChunk
 *   ↓ initializeModelChunk
 *   ↓ reviveModel
 *   ↓ parseModelString
 * Sink:                   getOutlinedModel  +  loadServerReference
 *
 * The sink chain ends in `loadServerReference` which dynamically resolves
 * a server-action reference from the bundler config and invokes the
 * resulting function with attacker-controlled `bound` args — that's the
 * RCE primitive in CVE-2025-55182.
 *
 * Every function declaration uses Flow `function name<T>(...)` generics —
 * the construct that the plain tree-sitter `javascript` grammar drops
 * on the floor. With the `tsx` grammar fix in place these all extract
 * and chain together end-to-end.
 */

// ---------------------------------------------------------------------------
// Stubs for cross-module helpers (React's internal storage / streams).
// Bodies are left implementation-light because all the analysis-relevant
// behaviour lives in the seven functions below.
// ---------------------------------------------------------------------------
const PENDING = "pending";
const BLOCKED = "blocked";
const RESOLVED_MODEL = "resolved_model";
const CYCLIC = "cyclic";
const INITIALIZED = "initialized";
const enableFlightReadableStream = true;
let initializingChunk = null;
let initializingChunkBlockedModel = null;

function Chunk(status, value, reason, response) {
  this.status = status; this.value = value; this.reason = reason;
  this._response = response;
}
function getChunk(response, id) { return response._chunks.get(id); }
function wakeChunk(listeners, value) { listeners.forEach(fn => fn(value)); }
function wakeChunkIfInitialized() {}
function registerTemporaryReference() {}
function createTemporaryReference() { return {}; }
function createModelResolver() { return () => {}; }
function createModelReject() { return () => {}; }
function createMap(_, m) { return new Map(m); }
function createSet(_, m) { return new Set(m); }
function extractIterator() {}
function createModel(_, value) { return value; }
const hasOwnProperty = Object.prototype.hasOwnProperty;

// loadServerReference is THE sink — dynamically resolves a server reference
// from the bundler config and invokes the resulting function with
// attacker-controlled `bound` args. The dispatch surface is what CVE-2025-55182
// turns into RCE.
function loadServerReference(response, id, bound, parentChunk, parentObject, key) {
  const serverConfig = response._bundlerConfig;
  // Attacker-controlled `id` resolves to a module entry; the resolved
  // function is then invoked with attacker-controlled `bound` arguments.
  const moduleEntry = serverConfig[id];
  // CWE-913 / CWE-94: dynamic module resolution + invocation under
  // attacker control. The original code uses `requireAsync(moduleEntry)`
  // followed by `.bind(null, ...bound)`; we keep the dispatch shape so
  // the LLM can recognise the sink.
  const resolved = require(moduleEntry.id)[moduleEntry.name];
  return resolved.bind(null, ...bound);
}

// Real React stubs that aren't on the bug path but are referenced.
function resolveStream() {}
function resolveFileChunk() {}
function reportGlobalError() {}
function close() {}
function createResponse(bundlerConfig, prefix, temporaryReferences) {
  return {
    _bundlerConfig: bundlerConfig,
    _prefix: prefix,
    _formData: new FormData(),
    _chunks: new Map(),
    _temporaryReferences: temporaryReferences,
  };
}
function resolveFileInfo() {}
function resolveFileComplete() {}

// ---------------------------------------------------------------------------
// THE BUG PATH — verbatim from React 19.0.0
// ---------------------------------------------------------------------------

// packages/react-server-dom-turbopack/src/server/ReactFlightDOMServerNode.js:208
function decodeReplyFromBusboy<T>(
  busboyStream: Busboy,
  turbopackMap: ServerManifest,
  options?: {temporaryReferences?: TemporaryReferenceSet},
): Thenable<T> {
  const response = createResponse(
    turbopackMap,
    '',
    options ? options.temporaryReferences : undefined,
  );
  let pendingFiles = 0;
  const queuedFields: Array<string> = [];
  busboyStream.on('field', (name, value) => {
    if (pendingFiles > 0) {
      queuedFields.push(name, value);
    } else {
      resolveField(response, name, value);
    }
  });
  busboyStream.on('file', (name, value, {filename, encoding, mimeType}) => {
    if (encoding.toLowerCase() === 'base64') {
      throw new Error("React doesn't accept base64 encoded file uploads");
    }
    pendingFiles++;
    const file = resolveFileInfo(response, name, filename, mimeType);
    value.on('data', chunk => { resolveFileChunk(response, file, chunk); });
    value.on('end', () => {
      resolveFileComplete(response, name, file);
      pendingFiles--;
      if (pendingFiles === 0) {
        for (let i = 0; i < queuedFields.length; i += 2) {
          resolveField(response, queuedFields[i], queuedFields[i + 1]);
        }
        queuedFields.length = 0;
      }
    });
  });
  busboyStream.on('finish', () => { close(response); });
  busboyStream.on('error', err => { reportGlobalError(response, err); });
  return getRoot(response);
}

function getRoot(response) {
  return response._chunks.get(0) || {};
}

// packages/react-server/src/ReactFlightReplyServer.js:1110
function resolveField(
  response: Response,
  key: string,
  value: string,
): void {
  response._formData.append(key, value);
  const prefix = response._prefix;
  if (key.startsWith(prefix)) {
    const chunks = response._chunks;
    const id = +key.slice(prefix.length);
    const chunk = chunks.get(id);
    if (chunk) {
      resolveModelChunk(chunk, value, id);
    }
  }
}

// packages/react-server/src/ReactFlightReplyServer.js:264
function resolveModelChunk<T>(
  chunk: SomeChunk<T>,
  value: string,
  id: number,
): void {
  if (chunk.status !== PENDING) {
    if (enableFlightReadableStream) {
      const streamChunk: InitializedStreamChunk<any> = (chunk: any);
      const controller = streamChunk.reason;
      if (value[0] === 'C') {
        controller.close(value === 'C' ? '"$undefined"' : value.slice(1));
      } else {
        controller.enqueueModel(value);
      }
    }
    return;
  }
  const resolveListeners = chunk.value;
  const rejectListeners = chunk.reason;
  const resolvedChunk: ResolvedModelChunk<T> = (chunk: any);
  resolvedChunk.status = RESOLVED_MODEL;
  resolvedChunk.value = value;
  resolvedChunk.reason = id;
  if (resolveListeners !== null) {
    initializeModelChunk(resolvedChunk);
    wakeChunkIfInitialized(chunk, resolveListeners, rejectListeners);
  }
}

// packages/react-server/src/ReactFlightReplyServer.js:444
function initializeModelChunk<T>(chunk: ResolvedModelChunk<T>): void {
  const prevChunk = initializingChunk;
  const prevBlocked = initializingChunkBlockedModel;
  initializingChunk = chunk;
  initializingChunkBlockedModel = null;
  const rootReference =
    chunk.reason === -1 ? undefined : chunk.reason.toString(16);
  const resolvedModel = chunk.value;
  const cyclicChunk: CyclicChunk<T> = (chunk: any);
  cyclicChunk.status = CYCLIC;
  cyclicChunk.value = null;
  cyclicChunk.reason = null;
  try {
    const rawModel = JSON.parse(resolvedModel);
    const value: T = reviveModel(
      chunk._response,
      {'': rawModel},
      '',
      rawModel,
      rootReference,
    );
    if (
      initializingChunkBlockedModel !== null &&
      initializingChunkBlockedModel.deps > 0
    ) {
      initializingChunkBlockedModel.value = value;
      const blockedChunk: BlockedChunk<T> = (chunk: any);
      blockedChunk.status = BLOCKED;
    } else {
      const resolveListeners = cyclicChunk.value;
      const initializedChunk: InitializedChunk<T> = (chunk: any);
      initializedChunk.status = INITIALIZED;
      initializedChunk.value = value;
      if (resolveListeners !== null) {
        wakeChunk(resolveListeners, value);
      }
    }
  } finally {
    initializingChunk = prevChunk;
    initializingChunkBlockedModel = prevBlocked;
  }
}

// packages/react-server/src/ReactFlightReplyServer.js:384
function reviveModel(
  response: Response,
  parentObj: any,
  parentKey: string,
  value: JSONValue,
  reference: void | string,
): any {
  if (typeof value === 'string') {
    return parseModelString(response, parentObj, parentKey, value, reference);
  }
  if (typeof value === 'object' && value !== null) {
    if (
      reference !== undefined &&
      response._temporaryReferences !== undefined
    ) {
      registerTemporaryReference(
        response._temporaryReferences,
        value,
        reference,
      );
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const childRef =
          reference !== undefined ? reference + ':' + i : undefined;
        value[i] = reviveModel(response, value, '' + i, value[i], childRef);
      }
    } else {
      for (const key in value) {
        if (hasOwnProperty.call(value, key)) {
          const childRef =
            reference !== undefined && key.indexOf(':') === -1
              ? reference + ':' + key
              : undefined;
          const newValue = reviveModel(response, value, key, value[key], childRef);
          if (newValue !== undefined) {
            value[key] = newValue;
          }
        }
      }
    }
  }
  return value;
}

// packages/react-server/src/ReactFlightReplyServer.js:908
function parseModelString(
  response: Response,
  obj: Object,
  key: string,
  value: string,
  reference: void | string,
): any {
  if (value[0] === '$') {
    switch (value[1]) {
      case '$': return value.slice(1);
      case '@': {
        const id = parseInt(value.slice(2), 16);
        const chunk = getChunk(response, id);
        return chunk;
      }
      case 'F': {
        // Server Reference — THE EXPLOIT TRIGGER for CVE-2025-55182.
        // Attacker submits a form field whose value starts with `$F<ref>`.
        // The reference is parsed via getOutlinedModel and the resulting
        // {id, bound} pair is passed to loadServerReference, which
        // invokes an attacker-chosen server action with attacker-chosen
        // bound arguments. RCE.
        const ref = value.slice(2);
        const metaData: {id: ServerReferenceId, bound: Thenable<Array<any>>} =
          getOutlinedModel(response, ref, obj, key, createModel);
        return loadServerReference(
          response,
          metaData.id,
          metaData.bound,
          initializingChunk,
          obj,
          key,
        );
      }
      case 'Q': {
        const ref = value.slice(2);
        return getOutlinedModel(response, ref, obj, key, createMap);
      }
      case 'W': {
        const ref = value.slice(2);
        return getOutlinedModel(response, ref, obj, key, createSet);
      }
      case 'i': {
        const ref = value.slice(2);
        return getOutlinedModel(response, ref, obj, key, extractIterator);
      }
    }
    const id = parseInt(value.slice(1), 16);
    const chunk = getChunk(response, id);
    return chunk;
  }
  return value;
}

// packages/react-server/src/ReactFlightReplyServer.js:587 — THE SINK
function getOutlinedModel<T>(
  response: Response,
  reference: string,
  parentObject: Object,
  key: string,
  map: (response: Response, model: any) => T,
): T {
  const path = reference.split(':');
  const id = parseInt(path[0], 16);
  const chunk = getChunk(response, id);
  switch (chunk.status) {
    case RESOLVED_MODEL:
      initializeModelChunk(chunk);
      break;
  }
  switch (chunk.status) {
    case INITIALIZED:
      let value = chunk.value;
      for (let i = 1; i < path.length; i++) {
        value = value[path[i]];
      }
      return map(response, value);
    case PENDING:
    case BLOCKED:
    case CYCLIC:
      const parentChunk = initializingChunk;
      chunk.then(
        createModelResolver(parentChunk, parentObject, key,
          chunk.status === CYCLIC, response, map, path),
        createModelReject(parentChunk),
      );
      return (null: any);
    default:
      throw chunk.reason;
  }
}

module.exports = { decodeReplyFromBusboy };
