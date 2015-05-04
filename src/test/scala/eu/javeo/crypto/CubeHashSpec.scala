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

  "Initial state of a digest" should "reflect the parameters" in {
    val test224 = new CubeHash(224)
    val state224 = CubeHash.hexValueOf(test224.peek)
    assert(state224.equals("1782FCB0901AEE1B221A9E8242C36263301CD92424AAA703C82137A6"))
    val test256 = new CubeHash(256)
    val state256 = CubeHash.hexValueOf(test256.peek)
    assert(state256.equals("B4D42BEA9FF2D6CC717E1163AE1E48355B2D5122634ED9E53141627EBE12CCF4"))
  }

  "The digest of an empty message" should "be the same as presented to NIST" in {
    val digest256 = CubeHash.hexValueOf(new CubeHash(256).digest(""))
    assert(digest256.equalsIgnoreCase("44c6de3ac6c73c391bf0906cb7482600ec06b216c7c54a2a8688a6a42676577d"))
    println(digest256)
  }

}
