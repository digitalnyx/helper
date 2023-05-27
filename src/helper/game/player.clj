(ns helper.game.player
  (:require
   [clojure.core.async :as async]
   [helper.game.events :as event]
   [helper.game.actions :as action]
   [helper.game.util :as u]
   [helper.network.realmd.connection :as realmd]
   [helper.network.world.connection :as world]
   [helper.auth.crypto :refer 
    [build-head-decrypter build-head-encrypter]]
   [helper.utils.conversions :as conv]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

;; (tcp.dstport == 3724 || tcp.srcport == 3724 || tcp.dstport == 8085 || tcp.srcport == 8085) && tcp.flags.push == 1

(defn logon
  [player]

  (debug "Attempting to logon player:" @player)

  (if (and
       (< 5 (:logon-attempts @player 0))
       ;; Other items that prevent logon... quit out.
       )
    ;; Failed check
    (u/set-state player :fatal-error)
    (if-let [conn (realmd/client
                      (get-in @player [:account :realmd-ip])
                      (get-in @player [:account :realmd-port])
                      (fn [pkt]
                        (event/process player pkt))
                      (fn []
                        (case (u/get-state player)
                          :logging-on
                          (do
                            (error "Realmd Closed Before Auth.")
                            (u/set-state player :fatal-error))
                          nil)))]

      (do
        (u/set-state player :logging-on)
        (swap! player assoc :realmd-connection conn)
        ;; TODO: Maybe have a callback to catch failed actions?
        (action/send-logon-challenge player))

      ;; No connection
      (u/set-state player :fatal-error))))

(defn decrypt-pkt
  [player pkt decrypter]
  ;;(debug (pr-str (conv/bytes->seq pkt)))
  (if (get-in @player [:world :authed?])
    (decrypter pkt 4)
    pkt))

(comment
  (defn do-play
    [player]
    (debug "Attempting to play...")
    ;;(close-connection (:realmd-connection @player))
    (u/set-state player :playing)

    (let [realm (get-realm player)
          server-ip (:address realm)
          port (:port realm)
          conn (world/client server-ip port)
          key (get-in @player [:auth :srp :crypto-key])
          decrypter (build-head-decrypter key)
          enc (build-head-encrypter key)
          _ (swap! player assoc-in [:world :encrypter] enc)
          _ (swap! player assoc :world-connection conn)
          buf (atom (clojure.lang.PersistentQueue/EMPTY))
          header (atom nil)]
      (if-not conn
        (u/set-state player :fatal-error)
        (while (= (u/get-state player) :playing)
          (let [in @(s/take! conn ::none)]
            (if (= in ::none)
              (do
                (error "Connection closed while playing.")
                (u/set-state player :fatal-error))
              (do
                ;; Add bytes from TCP stream to buffer
                (swap! buf into conj (conv/heap->bytes in))

                ;; We have enough bytes for a header
                (when (and (nil? @header)
                           (>= (count @buf) 4))
                  (reset!
                    header
                    (decrypt-pkt
                      player (take 4 @buf) decrypter))
                  (doall
                    (repeatedly 4 #(swap! buf pop))))

                ;; If we have a header and enough bytes
                (when (not (nil? @header))
                  (let [p-len (- (conv/bytes->int
                                   (take 2 @header)) 2)]
                    (when (>= (count @buf) p-len)
                      (event/process
                        player
                        (world/server-decode
                          (conv/into-bb
                            (concat @header
                                    (take p-len @buf)))))
                      (reset! header nil)
                      (doall
                        (repeatedly p-len #(swap! buf pop)))
                      )))))))))))

;; test player
;; Supply this as a loaded file
(def p 
  (atom 
   {:account 
    {:user "hosehead10"
     :pass "wanker"
     :timezone -6
     :local-ip "192.168.1.88"
     :realmd-ip "192.168.1.124"
     :realmd-port 3724
     :char "Shifty"}
    :state :offline
    :world {}}))

;; TODO: player atom 'reset' function
;;   - assign new uuid

(defn new-player
  [player]

  (async/thread
    ;; Run program while there are no fatal errors..
    (try
     (while (not= :fatal-error (u/get-state player))

       (case (u/get-state player)
        
         :offline
         (logon player)
        
         :authed
         ;;(do-play player)))
         (do
           (debug "Authed! Playing")
           (u/set-state player :fatal-error)))

       ;; Default
       (async/<!! (async/timeout 500)))
     (catch Exception e
       (error "Exception in player loop:" e)))

    ;; close any open ports
    (when-let [client (:realmd-connection @player)]
      (realmd/close-client client))
     (when-let [client (:world-connection @player)]
       (world/close-client client))
    ;;(close-connection (:realmd-connection @player))
    ;;(close-connection (:world-connection @player))
  
    (debug "Player loop exited.")

    ;; <! from channel to do actions from other files!
   
    ;;(async/<! (async/timeout 500))
    ))
