(ns helper.auth.srp6-test
  (:require
    [clojure.test :refer :all]
    [helper.auth.srp6 :refer :all]
    [helper.utils.conversions :as conv]))

;; Requires testing with a known 'a' value. 
;; TODO: Get a value from client in a recorded logon.

(def server-seed
  (BigInteger. "186142E4" 16))

(def session-key
  (BigInteger.
    (str "1084662137584108304918269110"
         "8922565844795699195116766765"
         "6485451062051497538558548453"
         "6031477610984") 10))

(def proof
  {:client-seed 912919983
   :proof       559237127060560165026235638687881129502699347744})

(def srp-vals
  {:I "HOSEHEAD10"
   :crypto-key
      [-127, -1, 108, 127, -88, -8, 29, -1, -25, -122, -91, -127, -79,
       -61, 8, 26, -119, -100, 41, 41, -52, -63, 10, 100, -86, -122,
       -87, -56, -37, 5, 121, -80, 40, 87, -116, 2, 102, 61, -71, -24]})

(deftest byte-conversions

  (testing "world auth"

    ;; Seeds always change but this is useful for debugging
    (comment
      (is (= proof
             (do-world-proof
               srp-vals server-seed))))

    )
  )
