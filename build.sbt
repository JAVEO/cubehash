organization := "JAVEO"

name := "cubehash"

version := "0.1.0"

licenses := Seq(
  ("MIT", url(s"https://github.com/${organization.value}/${name.value}/blob/master/LICENSE")))

homepage := Some(url(s"https://github.com/${organization.value}/${name.value}"))

scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked")

crossScalaVersions := Seq("2.10.4", "2.11.5")

scalaVersion := crossScalaVersions.value.last

libraryDependencies ++= Seq("org.scalatest" %% "scalatest" % "2.2.1" % "test")

pomExtra  := (
  <scm>
    <url>git@github.com:{organization.value}/{name.value}.git</url>
    <connection>scm:git:git@github.com:{organization.value}/{name.value}.git</connection>
  </scm>
  <developers>
    <developer>
      <id>{organization.value}</id>
      <name>Jacek Zadrag</name>
      <url>https://github.com/{organization.value}</url>
    </developer>
  </developers>)

