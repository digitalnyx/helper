(ns helper.utils.conversions
  (:import
    (java.math BigInteger)
    (java.nio ByteBuffer))
  (:require
    [gloss.data.primitives :refer
     [byte->ubyte
      to-byte]]
    [byte-streams :refer
     [bytes=
      to-byte-array]]))

(def default-endian :little)

(defprotocol HexDump
  "Convert things to a readable hex dump"
  (hex-dump [this] "HexDump"))

(defn col->hex-string
  [col]
  (apply
    str
    (interpose
      " "
      (map #(format "0x%02X" %) col))))

(def ^{:private true} bytes-class (Class/forName "[B"))
(extend bytes-class
  HexDump
  {:hex-dump
   col->hex-string})

(extend clojure.lang.PersistentList
  HexDump
  {:hex-dump
   col->hex-string})

(extend clojure.lang.PersistentVector
  HexDump
  {:hex-dump
   col->hex-string})

(extend java.nio.HeapByteBuffer
  HexDump
  {:hex-dump
   #(col->hex-string
      (.array ^java.nio.HeapByteBuffer %))})

(defn ubyte
  [byte]
  (byte->ubyte byte))

(defn ba->hex
  [ba]
  (map #(format "0x%02X" (ubyte %)) ba))

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

(defn seq->ba
  [col]
  (let [len (count col)
        ba (byte-array len)]
    (doseq [i (range len)]
      (aset-byte ba i (unchecked-byte (nth col i))))
    ba))

(defn ^bytes seq->bytes
  "Converts a list or vector to an unchecked native byte array."
  [s]
  (into-array Byte/TYPE (map unchecked-byte s)))

(defn bytes->seq
  [^bytes byte-array]
  (map ubyte byte-array))                                   ;;was int

(defn bytes->float
  [^bytes raw-bytes]
  (.getFloat
    ^ByteBuffer
    (ByteBuffer/wrap (seq->bytes raw-bytes))))

(defn bytes->int
  [^bytes byts]
  (loop [i (first byts)
         j (next byts)]
    (if (nil? j)
      i
      (recur (bit-or
               (bit-shift-left (ubyte i) 8)
               (ubyte (first j)))
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
  (let [ba (.toByteArray ^BigInteger (biginteger big-num))]
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

(defn ip-string->int
  [ip-string & {:keys [reverse?] :or {reverse? false}}]
  (let [ba (ip-string->bytes ip-string)
        bytes (if reverse? (reverse ba) ba)]
    (bit-or
      (bit-shift-left (nth bytes 0) 24)
      (bit-shift-left (nth bytes 1) 16)
      (bit-shift-left (nth bytes 2) 8)
      (nth bytes 3))))

(defn ip-string->string
  [ip-string & {:keys [reverse?] :or {reverse? false}}]
  (let [ba (ip-string->bytes ip-string)
        bytes (if reverse? (reverse ba) ba)]
    (apply str (map char bytes))))

(defn string->ip-string
  [string & {:keys [reverse?] :or {reverse? false}}]
  (let [ba (.getBytes ^String string)
        bytes (if reverse? (reverse ba) ba)]
    (apply
      str
      (interpose "." (map #(str (byte->ubyte %)) bytes)))))

(defn c-string->string
  [c-string & {:keys [reverse?] :or {reverse? false}}]
  (let [string (clojure.string/replace
                 c-string #"\u0000" "")]
    (if reverse?
      (apply str (reverse string))
      string)))

(defn string->c-string
  [string & {:keys [reverse?] :or {reverse? false}}]
  (let [c-string (apply str string "\0")]
    (if reverse?
      (apply str (reverse c-string))
      c-string)))

(defn reverse-string
  [string]
  (apply str (reverse string)))

(defn into-bb
  [coll]
  (let [size (count coll)
        buf (java.nio.ByteBuffer/allocate size)]
    (doseq [i (range size)]
      (.put buf i (to-byte (nth coll i))))
    buf))

(defn Heaps->formatted-bytes
  [heaps]
  (apply concat (for [heap heaps]
                  (map #(format "0x%02X" %)
                       (to-byte-array heap)))))

(defn heaps->bytes
  [heaps]
  (apply concat
         (for [heap heaps]
           (map #(byte->ubyte %)
                (to-byte-array heap)))))

(defn heap->bytes
  [heap]
  (map #(byte->ubyte %)
       (to-byte-array
         (flatten [heap]))))

(defn hex-dump-to-vec
  [dump]
  (->>
    (clojure.string/split dump #"\s+")
    (map str)
    (filter #(= 2 (count %)))
    (map #(str "0x" (clojure.string/upper-case %)))
    (interpose " ")
    (apply str)))

(defn value-to-hex
  [val]
  (->>
    (clojure.string/split val #":")
    ;(clojure.string/replace val #":" "")
    (reverse)
    (apply str)
    (str "0x")
    (read-string)
    (biginteger)
    (format "0x%X")))

(defn into-uint16-le
  [A B]
  (bit-or
    (bit-shift-left B 8) A))

(defn into-uint16-be
  [A B]
  (bit-or
    (bit-shift-left A 8) B))

(defn into-uint16
  [A B]
  (into-uint16-be A B))

(defn hex
  [num]
  (format "0x%X"
          (biginteger num)))

(defn heap->hex
  [^java.nio.HeapByteBuffer heap]
  (let [ba (.array heap)]
    (apply
      str
      (interpose
        " "
        (map #(format "0x%02X" %) ba)))))
