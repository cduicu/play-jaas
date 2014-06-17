name := "play-jaas"

organization := "net.duicu"

version := "1.1.1"

libraryDependencies ++= Seq(cache)

publishArtifact in Test := false

publishMavenStyle := true

play.Project.playJavaSettings

lazy val playJaas = project in file(".")