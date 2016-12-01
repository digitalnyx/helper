(ns helper.logon
  (:require
    [helper.packet.utils :refer :all]
    [helper.auth.srp6 :refer [do-srp]]
    [helper.packet.packer :refer :all]
    [helper.packet.unpacker :refer :all]
    [helper.packet.realmd :refer :all]
    [clojure.string :refer [upper-case]])
  (:import
    (java.io DataOutputStream
             DataInputStream)
    (java.net Socket)))

;; Just a thought - can't auto close the socket this way though...
(defn I-> 
  [account-name ^DataOutputStream out]
  )

;; Logon is special in this case, it needs to be synchronous and
;; it is a different port/address combo that the world server.
;; I would like to find a better way to handle this sometime.
(defn logon
  [account-name account-pass server-ip]
  (with-open [sock (Socket. ^String server-ip 3724)]
    (.setSoTimeout sock 5000)
    (let [out (DataOutputStream. (.getOutputStream sock))
          in (DataInputStream. (.getInputStream sock))
          ba (byte-array 1024)]
      (try
        ;; Step 1, send I to server
        (let [lc (pack (logon-challenge-> account-name "127.0.0.1"))]
          (.write out lc 0 (count lc)))

        (loop [creds {} done false]

          (if done
            creds
            (do
              (.read in ba)

              (cond

                (= 0 (first ba))
                ;; Step 2, receive challenge vars from server (B g N s)
                ;; Then send first proof.
                (let [lc (unpack (<-logon-challenge) ba)
                      computed-srp (do-srp account-name account-pass lc)
                      lp (pack (logon-proof-> (:A computed-srp) (:M1 computed-srp)))]
                  (.write out lp 0 (count lp))
                  (recur (assoc creds :credentials computed-srp) done))

                (= 1 (first ba))
                (let [lp (unpack (<-logon-proof) ba)
                      lr (pack (realm-list->))]
                  (.write out lr 0 (count lr))
                  (recur (assoc creds :credentials
                                      (assoc (:credentials creds) :M2 (:M2 lp))) done))

                (= 16 (first ba))
                (let [lr (unpack (<-realm-list (int (nth ba 7))) ba)]
                  (recur (assoc creds :realm-list (:realms lr)) true))

                :else
                (throw (Exception.
                         (str "Unknown opcode during logon: " (first ba))))))))


        (catch Exception e
          (clojure.stacktrace/print-stack-trace e))))))
