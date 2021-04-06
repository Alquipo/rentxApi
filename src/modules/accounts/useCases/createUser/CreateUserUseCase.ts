import { hash } from "bcrypt";
import { inject, injectable } from "tsyringe";

import { ICreateUserDTO } from "../../dtos/ICreateUserDTO";
import { IUsersRepository } from "../../repositories/IUsersRepository";

@injectable()
class CreateUserUseCase {
  constructor(
    @inject("UsersRepository")
    private userRepository: IUsersRepository
  ) {}

  async execute({
    name,
    driver_license,
    email,
    password,
  }: ICreateUserDTO): Promise<void> {
    const passwordHash = await hash(password, 8);

    await this.userRepository.create({
      name,
      driver_license,
      email,
      password: passwordHash,
    });
  }
}

export { CreateUserUseCase };
