namespace Notes_App.Features.Users;

public  class User
{
    public User(int id, string username, byte[] passwordSalt, byte[] passwordHash)
    {
        Id = id;
        Username = username;
        PasswordSalt = passwordSalt.ToArray();
        PasswordHash = passwordHash.ToArray();
    }

    public int Id { get; }
    public string Username { get; }

    public byte[] PasswordSalt { get; }
    public byte[] PasswordHash { get; }
}
