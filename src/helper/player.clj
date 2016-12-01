(ns helper.player
  (:require [clojure.core.async :as async]
            [helper.logon :refer [logon]]))

(defn play
  [params]
  (async/thread
    (let [player (atom {:params params
                        :connected? false
                        :playing? true})
          world-connection (atom nil)]
      (while (:playing? @player)
        
        (when-not (:connected? @player)
          ;; TODO: Create world connection from logon info
          (logon (:credentials (:params @player))))

        
        )))
  )
