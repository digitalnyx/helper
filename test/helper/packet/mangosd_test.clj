

(defn into-bb
  [coll]
  (let [size (count coll)
        buf (java.nio.ByteBuffer/allocate size)]
    (doseq [i (range size)]
      (.put buf i (conv/to-byte
                   (nth coll i))))
    buf))


(def test-pkt-1
  (into-bb [0x00 0x06 0xEC 0x01 0xB3 0x13 0x06 0xB7 0x22]))

(def test-header
  (into-bb [0x00 0x06 0xEC 0x01]))
