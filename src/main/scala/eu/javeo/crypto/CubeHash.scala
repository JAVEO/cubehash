package eu.javeo.crypto

class CubeHash(val bits: Int = 224, val blockLen: Int = 32, val rounds: Int = 16) {
  private val size  = 32
  private val halfSize = size / 2
  private val state = new Array[Int](size)
  assert(bits % 8 == 0, "CubeHash parameter bits should be multiple of 8")
  assert(bits > 0 & bits <= 512, "CubeHash parameter bits should be greater than 0 and less or equal 512")
  assert(blockLen > 0 & blockLen <= 128, "CubeHash parameter blockLen should not exceed 128")
  init

  private def stateAsBytes: Array[Byte] = {
    state.flatMap(CubeHash.intToBytes)
  }

  /**
   * Prepare initial state for digest
   */
  def init:CubeHash = {
    state(0) = bits / 8
    state(1) = blockLen
    state(2) = rounds
    for (i <- 3 until size) state(i) = 0
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
    for (i <- 1 to n * rounds) {
      addRotate(7, 25); swapXorSwap(8, 2)
      addRotate(11, 21); swapXorSwap(4, 1)
    }
  }

  /**
   * Update state with aligned block of bytes
   */
  def update(bytes: Array[Byte]) = {
    assert(bytes.length % blockLen == 0, s"Expected multiples of $blockLen bytes!")
    val iterator = bytes.sliding(4)
    while (iterator.hasNext) {
      for (i <- 0 to blockLen / 4)
          state(i) ^= CubeHash.bytesToInt(iterator.next())
      round(1)
    }
  }

  /**
   * Update state and finalize returning digest value
   */
  def digest(bytes: Array[Byte]): Array[Byte] = {
    val padding:Int = bytes.length % blockLen
    if (padding > 0) {
      val nopad = bytes.length - padding
      update(bytes.slice(0, nopad))
      val padded = new Array[Byte](blockLen)
      bytes.slice(nopad, bytes.length).copyToArray(padded)
      padded(padding) = 0x80.toByte
      update(padded)
    } else update(bytes)
    digest
  }

  def digest(str: String): Array[Byte] = {
    digest(str.getBytes)
  }

  /**
   * Take a look at state (for testing)
   */
  def peek: Array[Byte] = {
    stateAsBytes.slice(0, bits / 8)
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

object CubeHash {

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

  def hexValueOf(buf: Array[Byte]): String = buf.map("%02X" format _).mkString
}
