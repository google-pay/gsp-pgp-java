// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.google.samples.pgp;

import java.util.List;
import java.util.Optional;

/**
 * A source of PGP keys.
 * Generic types:
 *  T - Public key type
 *  S - Secret key type
 *  P - Private key type
 */
public interface KeyProvider<T, S, P> {
    List<T> getPublicKeys(String... userIds);
    List<S> getSecretKeys(String... userIds);
    Optional<P> getPrivateKey(Long keyId);
}
