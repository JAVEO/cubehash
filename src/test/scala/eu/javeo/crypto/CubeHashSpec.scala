package eu.javeo.crypto

import org.scalatest._

class CubeHashSpec extends FlatSpec {

  info("Testing CubeHash digest")

  "An Integer converted to bytes" should "convert back to the same value" in {
    val testInt = 0xf4f3f2f1
    assert(CubeHash.bytesToInt(CubeHash.intToBytes(testInt)) == testInt)
  }

  it should "be little endian" in {
    val testInt = 1
    assert(CubeHash.intToBytes(testInt)(0).toInt == testInt)
  }

  "Initial state of a digest" should "reflect parameter values" in {
    val test224 = new CubeHash(224)
    val state224 = CubeHash.hexValueOf(test224.peek)
    assert(state224.equals("1782fcb0901aee1b221a9e8242c36263301cd92424aaa703c82137a6"))
    val test256 = new CubeHash(256)
    val state256 = CubeHash.hexValueOf(test256.peek)
    assert(state256.equals("b4d42bea9ff2d6cc717e1163ae1e48355b2d5122634ed9e53141627ebe12ccf4"))
  }

  "The digest of an empty message" should "be the same as presented to NIST" in {
    val digest256 = CubeHash.hexValueOf(new CubeHash(256).digest(""))
    assert(digest256 equals "44c6de3ac6c73c391bf0906cb7482600ec06b216c7c54a2a8688a6a42676577d")
    val digest512 = CubeHash.hexValueOf(new CubeHash(512).digest(""))
    assert(digest512 equals "4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32" +
                            "f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a")
  }

  "The digest of a short message" should "be the same as presented to NIST" in {
    val testMessage = "Hello"
    val digest256 = CubeHash.hexValueOf(new CubeHash(256).digest(testMessage))
    assert(digest256 equals "e712139e3b892f2f5fe52d0f30d78a0cb16b51b217da0e4acb103dd0856f2db0")
    val digest512 = CubeHash.hexValueOf(new CubeHash(512).digest(testMessage))
    assert(digest512 equals "dcc0503aae279a3c8c95fa1181d37c418783204e2e3048a081392fd61bace883" +
                            "a1f7c4c96b16b4060c42104f1ce45a622f1a9abaeb994beb107fed53a78f588c")
  }

  "The digest of a longer message" should "be the same as presented to NIST" in {
    val testMessage = "The quick brown fox jumps over the lazy dog"
    val digest256 = CubeHash.hexValueOf(new CubeHash(256).digest(testMessage))
    assert(digest256 equals "5151e251e348cbbfee46538651c06b138b10eeb71cf6ea6054d7ca5fec82eb79")
    val digest512 = CubeHash.hexValueOf(new CubeHash(512).digest(testMessage))
    assert(digest512 equals "bdba44a28cd16b774bdf3c9511def1a2baf39d4ef98b92c27cf5e37beb8990b7"+
                            "cdb6575dae1a548330780810618b8a5c351c1368904db7ebdf8857d596083a86")
  }

}
