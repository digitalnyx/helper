(ns helper.network.realmd.connection
  (:require
   [manifold.deferred :as d]
   [manifold.stream :as s]
   [clojure.edn :as edn]
   [aleph.tcp :as tcp]
   [gloss.io :as io]
   [helper.utils.conversions :as conv]
   [helper.network.realmd.packet.client :as client]
   [helper.network.realmd.packet.server :as server]
   [taoensso.timbre :as timbre
    :refer [log  trace  debug  info  warn  error  fatal]]))

;; (alter-var-root #'*out* (constantly *out*))
;; WireShark filter: tcp.dstport == 3724 || tcp.srcport == 3724

;; TODO: send function that tries to encode first?

(defn- wrap-duplex-stream-client
  [s]
  (let [out (s/stream)]
    (s/connect
      (s/map #(io/encode client/realmd %) out)
      s)
    (s/splice
      out
      (io/decode-stream s server/realmd))))

(defn- client-connection
  [host port]
  (try
   @(d/chain 
     (tcp/client {:host host, :port port})
     #(wrap-duplex-stream-client %))
   (catch Exception e
     (error "Could not connect to client" 
            host ":" port "" e)
     nil)))

(defn close-client
  [client]
  ((:close client)))

;; TODO: Do this in world with boolean for encryption req
(defn write-client
  [client pkt]
  ((:write client) pkt))

;;
(defn client
  [host port on-event on-close]
  (when-let [conn (client-connection host port)]
    (s/consume on-event conn)
    (s/on-closed
      conn
      (fn []
        (debug "Realmd Client Connection Closed.")
        (on-close)))
    {:write
     ;; TODO: do something when this fails
     (fn [pkt]
       (s/put! conn pkt))
     :close
     (fn []
       (try
         (debug "Closing Readlmd Client Connection.")
         (.close ^manifold.stream.SplicedStream conn)
         (catch Exception e
           (error "Closing connection" e))))}))


;;(def c @(client "localhost" 10000))
;(def c @(connect "192.168.0.71" 3724))
;(s/put! c lc->)
;(s/take! c ::none)
;(s/consume #(reset! a %) c)
;(.close c)

;(def strm (s/stream))
;(def sd (io/decode-stream strm client/realmd))
;(d/error! sd (Exception. "boom"))


(defn serve
  [])
