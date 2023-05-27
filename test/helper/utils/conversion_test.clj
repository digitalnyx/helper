(ns helper.utils.conversions-test
  (:require 
   [clojure.test :refer :all]
   [helper.utils.conversions :refer :all]))

(deftest byte-conversions
  (testing "A single byte can be converted to an integer."
    (is (= 1 (byte 1)))
    (is (= 236 (byte 0xEC)))

    ;; This fails because 0xEC is too large for an unsigned byte
    (is (= 236 (first (into-array Byte/TYPE [0xEC]))))
    ))
