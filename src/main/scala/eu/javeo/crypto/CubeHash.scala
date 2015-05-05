package eu.javeo.crypto

/****************************************************************************
The MIT License (MIT)

Copyright (c) 2015 JAVEO Ltd.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*****************************************************************************/

/**
 * Compute CubeHash digest. This class is not thread safe.
 *
 * @param bits Digest bit length
 * @param blockLen Character block length
 * @param rounds Number of rounds per block
 * @param initRounds Number of initial rounds
 * @param finalRounds Number of final rounds
 */
class CubeHash(val bits: Int = 224, val blockLen: Int = 32,
               val rounds: Int = 16, val initRounds: Int = 160, val finalRounds: Int = 160) {
  assert(bits % 8 == 0, "CubeHash parameter bits should be multiple of 8")
  assert(bits > 0 & bits <= 512, "CubeHash parameter bits should be greater than 0 and less or equal 512")
  assert(blockLen > 0 & blockLen <= 128, "CubeHash parameter blockLen should not exceed 128")
  private val Size  = 32
  private val halfSize = Size / 2
  private val state = new Array[Int](Size)
  private val padded = new Array[Byte](blockLen)
  private var paddedLength = 0
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
    for (i <- 3 until Size) state(i) = 0
    round(initRounds)
    this
  }

  private def rotateLeft(value: Int, n: Int): Int = {
    (value << n) | (value >>> (32-n))
  }

  private def addRotate(r: Int) = {
    for (i:Int <- 0 until halfSize) {
      state(halfSize + i) += state(i)
      state(i) = rotateLeft(state(i), r)
    }
  }

  private def swapXorSwap(mask: Int) = {
    val mask2 = mask << 2
    for (i:Int <- 0 until halfSize) {
      if ((i & mask2) != 0) {
        val j = i ^ mask2
        val tmp = state(i) ^ state(j + halfSize)
        state(i) = state(j) ^ state(i + halfSize)
        state(j) = tmp
      }
    }
    for (i:Int <- halfSize until Size) {
      if ((i & mask) != 0) {
        val j = i ^ mask
        val tmp = state(i)
        state(i) = state(j)
        state(j) = tmp
      }
    }
  }

  private def round(n:Int) = {
    for (i <- 1 to n) {
      addRotate(7); swapXorSwap(2)
      addRotate(11); swapXorSwap(1)
    }
  }

  /**
   * Update state with aligned block of bytes
   */
  private def updateBlock(bytes: Array[Byte]) = {
    assert(bytes.length == blockLen, s"Expected multiple of $blockLen bytes!")
    val iterator = bytes.sliding(4, 4)
    for (i <- 0 until blockLen / 4)
      state(i) ^= CubeHash.bytesToInt(iterator.next())
    round(rounds)
  }

  /**
   * Update state with array of bytes
   * @param bytes content to update with
   */
  def update(bytes: Array[Byte]): Unit = {
    if (paddedLength > 0) { // take care of block leftovers
      bytes.copyToArray(padded, paddedLength)
      if (paddedLength + bytes.length < blockLen)
        paddedLength += bytes.length
      else {
        val bytesCopied = blockLen - paddedLength
        paddedLength = 0 // block is full, we have to process it
        updateBlock(padded)
        if (bytes.length - bytesCopied > 0) update(bytes.slice(bytesCopied, bytes.length))
      }
    } else {
      val iterator = bytes.sliding(blockLen, blockLen)
      while (iterator.hasNext) {
        val block = iterator.next()
        if (block.length == blockLen ) updateBlock(block)
        else {
          paddedLength = block.length
          block.copyToArray(padded)
        }
      }
    }
  }

  /**
   * Update state with a String
   * @param str content to update with
   */
  def update(str: String): Unit = {
    update(str.getBytes)
  }

  def update(b: Byte): Unit = {
    padded(paddedLength) = b
    paddedLength = (paddedLength + 1) % blockLen
    if (paddedLength == 0) updateBlock(padded)
  }

  /**
   * Get digest value
   * @param bytes content to digest
   */
  def digest(bytes: Array[Byte]): Array[Byte] = {
    update(bytes)
    digest
  }

  /**
   * Get digest value
   * @param str content to digest
   */
  def digest(str: String): Array[Byte] = {
    digest(str.getBytes)
  }

  /**
   * Take a look at digest state (for testing)
   */
  def peek: Array[Byte] = {
    stateAsBytes.slice(0, bits / 8)
  }

  /**
   * Finalize returning digest value
   */
  def digest: Array[Byte] = {
    padded(paddedLength) = 0x80.toByte
    for (i <- paddedLength + 1 until blockLen) padded(i) = 0
    paddedLength = 0
    updateBlock(padded)
    state(Size-1) ^= 1
    round(finalRounds)
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

  def hexValueOf(buf: Array[Byte]): String = buf.map("%02x" format _).mkString

  // Standard parameter values as defined by djb
  def SH192:CubeHash = new CubeHash(192)
  def SH224:CubeHash = new CubeHash(224)
  def SH256:CubeHash = new CubeHash(256)
  def SH512:CubeHash = new CubeHash(512)
  def HS128:CubeHash = new CubeHash(128,32,16,16,32)
  def HS160:CubeHash = new CubeHash(160,32,16,16,32)
  def HS192:CubeHash = new CubeHash(192,32,16,16,32)
  def HS224:CubeHash = new CubeHash(224,32,16,16,32)
  def HS256:CubeHash = new CubeHash(256,32,16,16,32)
  def HS384:CubeHash = new CubeHash(384,32,16,16,32)
  def HS512:CubeHash = new CubeHash(512,32,16,16,32)
  def HS512x:CubeHash = new CubeHash(512,1,16,16,32)
}
