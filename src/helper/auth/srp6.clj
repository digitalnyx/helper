;; This is a custom SRP6 implementation as non of the
;; Java libraries could manage it due to the following:
;;
;; -- ODD BEHAVIOR --
;; 1. The use of BigNum (BN) on *nix seems to store the
;;    bytes in reverse endian of the input, ex:
;;      _bn = BN_new();
;;      BN_hex2bn(&_bn, "0A0B0C0D");
;;      // Bytes in memory: [0D 0C 0B 0A]
;;    The BN docs specify Big Endian so I am lost here.
;;
;; 2. All of the Message Digests work on normal byte
;;    arrays (not reversed) and the BN arrays which.
;;
;; 3. Resulting Digest is converted to a BN so the hash
;;    needs to be reversed before creating the BN.
;;
;; 4. SRP S and the resulting KEY appear to have some
;;    sort of custom obfuscation.
;;
;; 5. The crypto functions make use of the session key 
;;    which is stored as a BN on *nix so I reverse it
;;    and store it as a second separate value (crypto-key).

(ns helper.auth.srp6
  (:require
   [helper.utils.conversions :refer :all]
   [clojure.string :refer [upper-case]]
   [taoensso.timbre :as timbre])
  (:import
   (java.security MessageDigest)))
(timbre/refer-timbre)

(defprotocol OpenSSL-bytes
  "Byte representation as seen in openSSL on x86 and x64."
  (openssl-bytes [this] "Weeeeeeeeeeeeeee!"))

(extend java.math.BigInteger
  OpenSSL-bytes
  {:openssl-bytes
   ;; When a BigNum is stored with BN_hex2bn on *nix,
   ;; the endian is reversed. Trying to mimic that.
   #(seq->bytes (reverse (big-num->bytes %)))})

(extend java.lang.String
  OpenSSL-bytes
  {:openssl-bytes
   ;; Bytes are read correctly as they are stored in
   ;; big endian on *nix.
   #(.getBytes ^String % "UTF-8")})

(extend clojure.lang.PersistentVector
  OpenSSL-bytes
  {:openssl-bytes
   ;; Assume bytes are correct endian
   #(seq->bytes %)})

(extend clojure.lang.PersistentList
  OpenSSL-bytes
  {:openssl-bytes
   ;; Assume bytes are correct endian
   #(seq->bytes %)})

(def ^{:private true} bytes-class (Class/forName "[B"))
(extend bytes-class
  OpenSSL-bytes
  {:openssl-bytes
   ;; Already in the correct format
   (fn [bytes] bytes)})

(defn sha-1
  "SHA-1 hash specific to this application (WoW)."
  [& objects]
  (let [md (MessageDigest/getInstance "SHA-1")]
    (doseq [object objects]
      (.update ^MessageDigest md
               ^bytes (openssl-bytes object)))
    (bytes->big-num
     (seq->bytes
      ;; When you take the hash of a BigNum on *nix, the byte
      ;; order of the BigNum is reversed and so to is the hash.
      (reverse (.digest ^MessageDigest md))))))

(defn- ^BigInteger compute-a
  "SRP value 'a' is a random 19 byte big-num."
  []
  (BigInteger. (* 19 8) (java.util.Random.)))

(defn- ^BigInteger compute-k
  "SRP value 'k' is just 3 for WoW."
  []
  (BigInteger. "3" 10))

(defn- ^BigInteger compute-user-hash
  "SHA-1 hash of username (upper) and password: H(I | ':' | P)"
  [^String user ^String pass]
  (sha-1 (upper-case (str user ":" pass))))

(defn- ^BigInteger compute-user2-hash
  "SHA-1 hash of the username (upper) only: H(I)"
  [^String user]
  (sha-1 (upper-case user)))

(defn- ^BigInteger compute-salted-hash
  "SHA-1 hash of salt and another hash: H(S | ?)"
  [^BigInteger salt ^BigInteger to-salt]
  (sha-1 salt to-salt))

(defn- ^BigInteger compute-N-g-hash
  "SHA-1 hash where each byte is N-hash(i) XOR g-hash(i)"
  [^BigInteger N ^BigInteger g]
  (bytes->big-num
    (map #(bit-xor %1 %2)
         (big-num->bytes (sha-1 N))
         (big-num->bytes (sha-1 g)))))

(defn- ^BigInteger compute-x
  "SRP value 'x' is a salt of the user hash: H(s | H(I | ':' | P))"
  [^String user ^String pass ^BigInteger salt]
  (compute-salted-hash
    salt
    (compute-user-hash user pass)))

(defn- ^BigInteger compute-v
  "SRP value 'v' is the verifier: g^x % N"
  [^BigInteger g ^BigInteger x ^BigInteger N]
  (.modPow g x N))

(defn- ^BigInteger compute-A
  "SRP value 'A' is the public client value: g^a % N"
  [^BigInteger g ^BigInteger a ^BigInteger N]
  (.modPow g a N))

(defn- ^BigInteger compute-u
  "SRP value 'u' is the random scrambling value: H(A | B)"
  [^BigInteger A ^BigInteger B]
  (sha-1 A B))

(defn- ^BigInteger compute-S
  "SRP value 'S' is the session key: (B - (k * v))^((u * x) + a) % N"
  [^BigInteger B ^BigInteger k ^BigInteger v
   ^BigInteger x ^BigInteger N ^BigInteger u ^BigInteger a]
  (.modPow
   (.subtract B (.multiply k v))
   (.add ^BigInteger (.multiply u x) a)
   N))

(defn- ^BigInteger compute-session-key
  "Must be a WoW specific step"
  [^BigInteger S]
  (let [S-evens (bytes->big-num 
                 (seq->bytes (take-nth 2 (big-num->bytes S))))
        S-evens-hash (big-num->bytes (sha-1 S-evens))
        S-odds  (bytes->big-num 
                 (seq->bytes (take-nth 2 (rest (big-num->bytes S)))))
        S-odds-hash  (big-num->bytes (sha-1 S-odds))]
     (bytes->big-num
       (seq->bytes
        (interleave S-evens-hash S-odds-hash)))))

(defn- ^BigInteger compute-M1
  "SRP value 'M1' is the first evidence message: 
  H(N-g-hash | user2-hash | s | A | B | session-key)"
  [^BigInteger A ^BigInteger B ^BigInteger s
   ^BigInteger N-g-hash ^BigInteger user2-hash ^BigInteger session-key]
  (sha-1 N-g-hash user2-hash s A B session-key))

(defn- ^BigInteger compute-M2
  "SRP value 'M2' is the second evidence message: H(A)"
  [^BigInteger A]
  (sha-1 A))

(defn- ^BigInteger compute-crc
  "Random 20 byte value for now..."
  []
  (BigInteger. (* 20 8) (java.util.Random.)))

(defn do-srp
  [user pass challenge]
  (comment
   (debug "B: " (.toString ^BigInteger (:B challenge) 16))
   (debug "g: " (.toString ^BigInteger (:g challenge) 16))
   (debug "N: " (.toString ^BigInteger (:N challenge) 16))
   (debug "s: " (.toString ^BigInteger (:s challenge) 16))
   ;;(debug "unk3: " (.toString ^BigInteger (:unk3 challenge) 16))
   )
  (let [a (compute-a)
        x (compute-x user pass (:s challenge))
        v (compute-v (:g challenge) x (:N challenge))
        A (compute-A (:g challenge) a (:N challenge))
        u (compute-u A (:B challenge))
        S (compute-S (:B challenge) (compute-k) v x (:N challenge) u a)
        s-key (compute-session-key S)
        ;; c-key (big-num->bytes s-key) ;; K
        c-key (reverse (big-num->bytes s-key)) ;; K
        user2 (compute-user2-hash user)
        Ng (compute-N-g-hash (:N challenge) (:g challenge))
        M1 (compute-M1 A (:B challenge) (:s challenge) Ng user2 s-key)]

    (comment
     (debug "a: " (.toString ^BigInteger a 16))
     (debug "x: " (.toString ^BigInteger x 16))
     (debug "v: " (.toString ^BigInteger v 16))
     (debug "A: " (.toString ^BigInteger A 16))
     (debug "u: " (.toString ^BigInteger u 16))
     (debug "S: " (.toString ^BigInteger S 16))
     (debug "s-key: " (.toString ^BigInteger s-key 16))
     (debug "Ng: " (.toString ^BigInteger Ng 16))
     (debug "M1: " (.toString ^BigInteger M1 16)))

    {:I (upper-case user)
     :a a :x x :v v :Ng Ng
     :A A :u u :M1 M1 :S S 
     :crc (compute-crc)
     :session-key s-key
     :crypto-key c-key}
    ))

(defn do-world-proof
  [srp-vals server-seed]
  (let [client-seed 
        (BigInteger. (* 4 8) (java.util.Random.))
        t (seq->bytes [0 0 0 0])]
   {:client-seed client-seed
    :proof
    (sha-1 
     (:I srp-vals)
     t
     client-seed
     server-seed
     (:crypto-key srp-vals))}))

