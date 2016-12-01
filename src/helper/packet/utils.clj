(ns helper.packet.utils
  (:import
   (java.math BigInteger)
   (java.nio ByteBuffer)))

(def default-endian :little)

(defn apply-endianess
  [endianess byte-list]
  (if (= :big endianess)
    byte-list
    (reverse byte-list)))

(defn ^int first-index-of
  [^bytes raw-bytes match]
  (loop [bs raw-bytes
         position 0]
    (cond

     (nil? bs)
     0

     (= match (first bs))
     (inc position)

     :else
     (recur (next bs) (inc position)))))

(defn ^bytes seq->bytes
  "Converts a list or vector to an unchecked native byte array."
  [s]
  (into-array Byte/TYPE (map unchecked-byte s)))

(defn bytes->float
  [^bytes raw-bytes]
  (.getFloat
   ^ByteBuffer
   (ByteBuffer/wrap (seq->bytes raw-bytes))))

(defn bytes->int
  [byts]
  (loop [i (first byts)
         j (next byts)]
    (if (nil? j)
      i
      (recur (bit-or
              (bit-shift-left (int i) 8)
              (int (first j)))
             (next j)))))

(defn int->bytes
  "Returns a BigEndian byte array representing an integer.
  @number - Positive whole number.
  @sizeof - Number of bytes to fill in array."
  [number sizeof]
  (loop [n number
         b '()]
    (if (= sizeof (count b))
      b
      (recur (bit-shift-right n 8)
             (cons (bit-and 16rFF n) b)))))

(defn ^BigInteger bytes->big-num
  [byts]
  (BigInteger. 1 ^bytes (seq->bytes byts)))

(defn ^bytes big-num->bytes
  [big-num]
  ;; need to remove sign bit padding if it occurred.
  (let [ba (.toByteArray ^BigInteger big-num)]
    (if (zero? (first ba))
      (seq->bytes (rest ba))
      ba)))

(defn ^bytes concat-byte-arrays
  [^bytes ba-1 ^bytes ba-2]
  (let [ba-n ^bytes (byte-array (+ (count ^bytes ba-1)
                                   (count ^bytes ba-2)))]
    (System/arraycopy ba-1 0 ba-n 0 (count ^bytes ba-1))
    (System/arraycopy ba-2 0 ba-n (count ^bytes ba-1)
                      (count ^bytes ba-2))
    ba-n))

(defn ^BigInteger concat-big-nums
  [big-num-1 big-num-2]
  (let [ba-1 ^bytes (big-num->bytes big-num-1)
        ba-2 ^bytes (big-num->bytes big-num-2)]
    (bytes->big-num (concat-byte-arrays ba-1 ba-2))))

(defn ip-string->bytes
  [ip-string]
  (map #(Integer/parseInt %)
       (clojure.string/split ip-string #"\.")))
