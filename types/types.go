package types

type Provider int

const (
	GITHUB Provider = iota
	FACEBOOK
	SPOTIFY
	APPLE
	METAMASK
)

func (p Provider) String() string {
	return [...]string{"GITHUB", "FACEBOOK", "SPOTIFY", "METAMASK"}[p]
}
