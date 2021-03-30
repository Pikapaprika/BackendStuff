package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
)

type UpdateArtifact struct {
	Header  UpdateHeader
	Payload *os.File
}

func SignSHA256Digest(keyPath string, hashVal [32]byte) (*[32]byte, error) {
	signer, err := NewRSASigner(keyPath)
	if err != nil {
		return nil, err
	}
	sig, err := signer.signSHA256Digest(hashVal)
	return sig, err
}


// Encrypt Update-Artifact symmetrically
func (artifact *UpdateArtifact) encrypt(symmetricKeyPath string) error {
	return nil
}

type UpdateHeader struct {
	// Sqn. needs to be managed by the publisher
	SequenceNumber   uint64
	HardwareUUID     [16]byte
	URILength        uint16
	URIData          []byte
	SHA256PayloadSum [32]byte
	// Signature = Hash(SequenceNumber || HardwareUUID || SHA256PayloadSum) :: müsste gleiche Länge wie SHA256 Hash sein
	Signature [32]byte
}

func UpdateHashBuilderWithUnsignedInt(val interface{}, hashBuilder hash.Hash) error {
	var buff []byte
	switch val.(type) {
	case uint16:
		buff = make([]byte, 16)
		binary.LittleEndian.PutUint16(buff, val.(uint16))
	case uint32:
		buff = make([]byte, 32)
		binary.LittleEndian.PutUint32(buff, val.(uint32))
	case uint64:
		buff = make([]byte, 64)
		binary.LittleEndian.PutUint64(buff, val.(uint64))
	default:
		return errors.New("not a valid type")
	}
	hashBuilder.Write(buff)
	return nil
}

func (artifact *UpdateArtifact) AddRSASignature(keyPath string) error {

	sig, err := SignSHA256Digest(keyPath, artifact.Header.SHA256PayloadSum)
	if err != nil {
		return err
	}
	artifact.Header.Signature = *sig
	return nil
}

func (header *UpdateHeader) AddSHA256FileSum(file *os.File, imageChunkSize uint32) error {
	hashbuilder := sha256.New()
	err := UpdateHashBuilderWithUnsignedInt(header.SequenceNumber, hashbuilder)
	if err != nil {
		return err
	}
	hashbuilder.Write(header.HardwareUUID[:])
	err = UpdateHashBuilderWithUnsignedInt(header.URILength, hashbuilder)

	if err != nil {
		return err
	}

	hashbuilder.Write(header.URIData)
	buffer := make([]byte, imageChunkSize)
	reader := bufio.NewReader(file)
	for {
		read, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		hashbuilder.Write(buffer[:read])
	}

	digest := hashbuilder.Sum(nil)
	if len(digest) != 32 {
		panic(errors.New("sha256 digest length should be 32"))
	}
	copy(header.SHA256PayloadSum[:], digest)

	return nil
}

/* Creates an Update-Artifact.
If URI is "", the Firmware-Image will be integrated into the artifact.
 */
func CreateArtifact(sequenceNumber uint64, hardwareUUID [16]byte, fwImagePath string, URI string, keyPath string) (*UpdateArtifact, error) {
	if fwImagePath == ""  {
		return nil, errors.New("must provide fwImagePath")
	}

	if keyPath == ""  {
		return nil, errors.New("must provide keyPath")
	}

	var header UpdateHeader
	if URI == "" {
		header = UpdateHeader{SequenceNumber: sequenceNumber,
			HardwareUUID: hardwareUUID, URILength: 0}
	} else {
		header = UpdateHeader{SequenceNumber: sequenceNumber,
			HardwareUUID: hardwareUUID, URILength: uint16(len(URI)), URIData: []byte(URI)}
	}

	image, err := os.Open(fwImagePath)
	if err != nil {
		return nil, err
	}
	err = header.AddSHA256FileSum(image, 2041)

	if err != nil {
		return nil, err
	}

	artifact := UpdateArtifact{
		Header:  header,
		Payload: image,
	}

	err = artifact.AddRSASignature(keyPath)

	return &artifact, err
}

func main() {
	art, err := CreateArtifact(1, [16]byte{0}, "","", "")
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println(art.Header.SHA256PayloadSum)
	}
}
