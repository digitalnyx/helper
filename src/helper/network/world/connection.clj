(ns helper.network.world.connection
  (:require
   [manifold.deferred :as dfrd]
   [manifold.stream :as strm]
   [clojure.edn :as edn]
   [aleph.tcp :as tcp]
   [gloss.io :as io]
   [helper.utils.conversions :as conv]
   [helper.network.world.packet.client :as client]
   [helper.network.world.packet.server :as server]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

(defn wrap-duplex-stream-client
  [s]
  (let [out (strm/stream)]
    (strm/connect
     out
     s)
    (strm/splice
      out
      s)))

(defn client
  [host port]
  (try
   @(dfrd/chain 
     (tcp/client {:host host, :port port})
     #(wrap-duplex-stream-client %))
   (catch Exception e
     (error "Could not connect to client" 
            host ":" port "" e)
     nil)))

(defn close-client
  [client]
  )

;; Return a function to close the connection
;; Return an error map when the connection closes
(comment
  (defn client-decode-stream
   [host port decrypter f]
   (when-let [conn (client host port)]
     )

   (let [in @(s/take! conn ::none)]
     (if (= in ::none)
       (do
         (error "Connection closed while playing.")
         (set-state player :fatal-error))
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
               ))))))
   ))

;; TODO: Add encryption options function
(defn server-encode
  [val]
  (server/encode val))

(defn server-decode
  [bytes]
  (server/decode bytes))

(defn client-encode
  [val]
  (client/encode val))

(defn client-decode
  [bytes]
  (client/decode bytes))
