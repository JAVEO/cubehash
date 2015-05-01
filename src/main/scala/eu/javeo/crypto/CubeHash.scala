package eu.javeo.crypto

class CubeHash(val hh: Int = 224, val bb: Int = 32, val rr: Int = 16) {
  private val size  = 32
  private val halfSize = size / 2
  private val state = new Array[Int](size)
  assert(hh % 8 == 0, "CubeHash parameter hh should be multiple of 8")
  assert(bb <= 128, "CubeHash parameter bb should not exceed 128")
  init

  def intToBytes(a: Int):Array[Byte] = {
    Array((a & 0xff).toByte, ((a >> 8) & 0xff).toByte,
      ((a >> 16) & 0xff).toByte, ((a >> 24) & 0xff).toByte)
  }

  def bytesToInt(bytes: Array[Byte]):Int = {
    (bytes(0) & 0xff) |
      ((bytes(1) & 0xff) << 8) |
      ((bytes(2) & 0xff) << 16) |
      ((bytes(3) & 0xff) << 24)
  }

  private def stateAsBytes: Array[Byte] = {
    state.flatMap(intToBytes)
  }

  /**
   * Prepare initial state for digest
   */
  def init:CubeHash = {
    state(0) = hh / 8
    state(1) = bb
    state(2) = rr
    for (i <- 3 to size) state(i) = 0
    round(10)
    this
  }

  private def addRotate(r: Int, s: Int) = {
    for (i:Int <- 0 until halfSize) {
      state(halfSize + i) += state(i)
      state(i) = (state(i) << r) ^ (state(i) >>> s)
    }
  }

  private def swapXorSwap(mask1: Int, mask2: Int) = {
    for (i:Int <- 0 until halfSize) {
      if ((i & mask1) != 0) {
        val j = i ^ mask1
        val tmp = state(i) ^ state(j + halfSize)
        state(i) = state(j) ^ state(i + halfSize)
        state(j) = tmp
      }
    }
    for (i:Int <- halfSize to size) {
      if ((i & mask2) != 0) {
        val j = i ^ mask2
        val tmp = state(i)
        state(i) = state(j)
        state(j) = tmp
      }
    }
  }

  private def round(n:Int) = {
    for (i <- 1 to n * rr) {
      addRotate(7, 25); swapXorSwap(8, 2)
      addRotate(11, 21); swapXorSwap(4, 1)
    }
  }

  /**
   * Update state with aligned block of bytes
   */
  def update(bytes: Array[Byte]) = {
    assert(bytes.length % bb == 0, s"Expected multiples of ${bb} bytes!")
    val iterator = bytes.sliding(4)
    while (iterator.hasNext) {
      for (i <- 0 to bb / 4)
          state(i) ^= bytesToInt(iterator.next())
      round(1)
    }
  }

  /**
   * Update state and finalize returning digest value
   */
  def digest(bytes: Array[Byte]): Array[Byte] = {
    val padding:Int = bytes.length % bb
    if (padding > 0) {
      val nopad = bytes.length - padding
      update(bytes.slice(0, nopad))
      val padded = new Array[Byte](bb)
      bytes.slice(nopad, bytes.length).copyToArray(padded)
      padded(padding) = 0x80.toByte
      update(padded)
    } else update(bytes)
    digest
  }

  /**
   * Take a look at state (for testing)
   */
  def peek: Array[Byte] = {
    stateAsBytes.slice(0, bb / 8)
  }

  /**
   * Finalize returning digest value
   */
  def digest: Array[Byte] = {
    state(size-1) ^= 1
    round(10)
    peek
  }
}
