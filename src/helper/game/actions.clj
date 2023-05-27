(ns helper.game.actions
  (:require
    [helper.auth.srp6 :as srp]
    [helper.utils.conversions :as conv]
    [helper.network.world.connection :as world]
    [helper.network.realmd.connection :as realmd]
    [taoensso.timbre :as timbre
     :refer [log trace debug info warn error fatal]]))

(defn- send-world-pkt
  [player pkt]
  )

(defn- send-realmd-pkt
  [player pkt]
  (realmd/write-client
    (:realmd-connection @player)
    pkt))

(defn send-logon-challenge
  [player]
  (let [acc-info (:account @player)]
    (send-realmd-pkt
      player
      {:opcode        :logon-challenge
       :game          "WoW"
       :version-major 1
       :version-mid   12
       :version-minor 1
       :build-number  5875
       :arch          "x86"
       :platform      "OSX"
       :locale        "enUS"
       :time-bias     (:timezone acc-info)
       :client-ip     (:local-ip acc-info)
       :account-name  (:user acc-info)})))

(defn send-logon-proof
  [player]
  (let [user (get-in @player [:account :user])
        pass (get-in @player [:account :pass])
        challenge (get-in @player [:auth :challenge])
        srp-vals (srp/do-srp user pass challenge)]
    (swap! player assoc-in [:auth :srp] srp-vals)
    (send-realmd-pkt
      player
      {:opcode         :logon-proof
       :A              (:A srp-vals)
       :M1             (:M1 srp-vals)
       :crc            (:crc srp-vals)
       :key-count      0
       :security-flags 0})))

(defn send-realm-list
  [player]
  (send-realmd-pkt
    player
    {:opcode :realm-list}))

(defn encrypt-pkt
  [player pkt]
  (let [pkt (world/client-encode pkt)
        encrypt (get-in @player [:world :encrypter])]
    ;;(debug "Class of encoded pkt:" (class pkt))
    (if (get-in @player [:world :authed?])
      (conv/into-bb
        (encrypt
          (conv/heaps->bytes pkt) 6))
      pkt)))

(defn send-auth-challenge
  [player server-seed]
  (send-world-pkt
    player
    (let [proof (srp/do-world-proof
                  (get-in @player [:auth :srp])
                  server-seed)]
      (encrypt-pkt
        player
        {:opcode       :auth-session
         :client-build 5875
         :I
                       (get-in @player [:auth :srp :I])
         :client-seed
                       (:client-seed proof)
         :client-proof
                       (:proof proof)})))
  ;; If proof fails, connection is just closed.
  (swap! player assoc-in [:world :authed?] true))

(defn send-char-enum
  [player]
  (send-world-pkt
    player
    (encrypt-pkt
      player
      {:opcode :char-enum})))

(defn send-char-login
  [player guid]
  (send-world-pkt
    player
    (encrypt-pkt
      player
      {:opcode :char-login
       :guid   guid})))
